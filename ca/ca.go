package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/liboqs_sig"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/wrap"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
)

const (
	rootCAPrefix          = "Pebble Root CA "
	intermediateCAPrefix  = "Pebble Intermediate CA "
	interWrappedCAPrefix  = "Pebble Wrapped CA "
	defaultValidityPeriod = 157766400
)

type CAImpl struct {
	log              *log.Logger
	db               *db.MemoryStore
	ocspResponderURL string

	chains []*chain

	certValidityPeriod uint
}

type chain struct {
	root          *issuer
	intermediates []*issuer
	wrapped       []*issuer
}

func (c *chain) String() string {
	fullchain := append(c.intermediates, c.root)
	n := len(fullchain)

	names := make([]string, n)
	for i := range fullchain {
		names[n-i-1] = fullchain[i].cert.Cert.Subject.CommonName
	}
	return strings.Join(names, " -> ")
}

type issuer struct {
	key  crypto.Signer
	cert *core.Certificate
}

func makeSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(fmt.Sprintf("unable to create random serial number: %s", err.Error()))
	}
	return serial
}

// Taken from https://github.com/cloudflare/cfssl/blob/b94e044bb51ec8f5a7232c71b1ed05dbe4da96ce/signer/signer.go#L221-L244
func makeSubjectKeyID(key crypto.PublicKey) ([]byte, error) {
	// Marshal the public key as ASN.1
	pubAsDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	// Unmarshal it again so we can extract the key bitstring bytes
	var pubInfo struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(pubAsDER, &pubInfo)
	if err != nil {
		return nil, err
	}

	// Hash it according to https://tools.ietf.org/html/rfc5280#section-4.2.1.2 Method #1:
	ski := sha1.Sum(pubInfo.SubjectPublicKey.Bytes)
	return ski[:], nil
}

// makeKey and makeRootCert are adapted from MiniCA:
// https://github.com/jsha/minica/blob/3a621c05b61fa1c24bcb42fbde4b261db504a74f/main.go

// makeKey creates a new 2048 bit RSA private key and a Subject Key Identifier
func makeKey() (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	ski, err := makeSubjectKeyID(key.Public())
	if err != nil {
		return nil, nil, err
	}
	return key, ski, nil
}

func makeECDSAKey(securityLevel int) (*ecdsa.PrivateKey, []byte, error) {
	var curve elliptic.Curve
	switch securityLevel {
	case 1:
		curve = elliptic.P256()
	case 3:
		curve = elliptic.P384()
	case 5:
		curve = elliptic.P521()
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	ski, err := makeSubjectKeyID(key.Public())
	if err != nil {
		return nil, nil, err
	}
	return key, ski, nil
}


func (ca *CAImpl) makeRootCert(
	subjectKey crypto.Signer,
	subject pkix.Name,
	subjectKeyID []byte,
	signer *issuer) (*core.Certificate, error) {

	serial := makeSerial()
	template := &x509.Certificate{
		Subject:      subject,
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(30, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SubjectKeyId:          subjectKeyID,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	var signerKey crypto.Signer
	var parent *x509.Certificate
	if signer != nil && signer.key != nil && signer.cert != nil && signer.cert.Cert != nil {
		signerKey = signer.key
		parent = signer.cert.Cert
	} else {
		signerKey = subjectKey
		parent = template
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, subjectKey.Public(), signerKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	hexSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
	newCert := &core.Certificate{
		ID:   hexSerial,
		Cert: cert,
		DER:  der,
	}
	if signer != nil && signer.cert != nil {
		newCert.IssuerChains = make([][]*core.Certificate, 1)
		newCert.IssuerChains[0] = []*core.Certificate{signer.cert}
	}
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, err
	}
	return newCert, nil
}
func (ca *CAImpl) makeWrappedCert(
	subjectKey crypto.Signer,
	subject pkix.Name,
	subjectKeyID []byte,
	signer *issuer,
	certPSK []byte) (*core.Certificate, error) {

	serial := makeSerial()
	template := &x509.Certificate{
		Subject:      subject,
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(30, 0, 0),

		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          subjectKeyID,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}	
	
	signerKey := signer.key
	parent := signer.cert.Cert

	subjectPk := subjectKey.Public()	
	
	subjectECDSAPk, ok := subjectPk.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("wrapped issuer key must be an ECDSA key")
	}

	pk := elliptic.Marshal(subjectECDSAPk.Curve, subjectECDSAPk.X, subjectECDSAPk.Y)
	
	// pk, err := x509.MarshalPKIXPublicKey(subjectKey.Public())
	// if err != nil {
	// 	return nil, err
	// }

	wrapped, err := wrap.WrapPublicKey(pk, certPSK)
	if err != nil {
		return nil, err
	}

	wrapPub := new(wrap.PublicKey)
	wrapPub.WrappedPk = wrapped
	wrapPub.ClassicAlgorithm = subjectECDSAPk.Curve

	der, err := x509.CreateCertificate(rand.Reader, template, parent, wrapPub, signerKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	hexSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
	newCert := &core.Certificate{
		ID:   hexSerial,
		Cert: cert,
		DER:  der,
	}
	
	newCert.IssuerChains = make([][]*core.Certificate, 1)
	newCert.IssuerChains[0] = []*core.Certificate{signer.cert}
	
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, err
	}
	return newCert, nil
}


func (ca *CAImpl) newRootIssuer(name string) (*issuer, error) {
	// Make a root private key
	
	// rk, subjectKeyID, err := makeKey()
	rk, subjectKeyID, err := makeECDSAKey(5)

	if err != nil {
		return nil, err
	}
	// Make a self-signed root certificate
	subject := pkix.Name{
		CommonName: rootCAPrefix + name,
	}
	rc, err := ca.makeRootCert(rk, subject, subjectKeyID, nil)
	if err != nil {
		return nil, err
	}

	ca.log.Printf("Generated new root issuer %s with serial %s and SKI %x\n", rc.Cert.Subject, rc.ID, subjectKeyID)
	return &issuer{
		key:  rk,
		cert: rc,
	}, nil
}

func (ca *CAImpl) newIntermediateIssuer(root *issuer, intermediateKey crypto.Signer, subject pkix.Name, subjectKeyID []byte) (*issuer, error) {
	if root == nil {
		return nil, fmt.Errorf("Internal error: root must not be nil")
	}
	// Make an intermediate certificate with the root issuer
	ic, err := ca.makeRootCert(intermediateKey, subject, subjectKeyID, root)
	if err != nil {
		return nil, err
	}
	ca.log.Printf("Generated new intermediate issuer %s with serial %s and SKI %x\n", ic.Cert.Subject, ic.ID, subjectKeyID)
	return &issuer{
		key:  intermediateKey,
		cert: ic,
	}, nil
}
func (ca *CAImpl) newWrappedIssuer(root *issuer, intermediateKey crypto.Signer, subject pkix.Name, subjectKeyID []byte, psk []byte) (*issuer, error) {
	if root == nil {
		return nil, fmt.Errorf("Internal error: root must not be nil")
	}
	// Make an intermediate certificate with the root issuer
	ic, err := ca.makeWrappedCert(intermediateKey, subject, subjectKeyID, root, psk)
	if err != nil {
		return nil, err
	}
	ca.log.Printf("Generated new intermediate issuer %s with serial %s and SKI %x\n", ic.Cert.Subject, ic.ID, subjectKeyID)
	return &issuer{
		key:  intermediateKey,
		cert: ic,
	}, nil
}

// newChain generates a new issuance chain, including a root certificate and numIntermediates intermediates (at least 1).
// The first intermediate will use intermediateKey, intermediateSubject and subjectKeyId.
// Any intermediates between the first intermediate and the root will have their keys and subjects generated automatically.
func (ca *CAImpl) newChain(intermediateKey crypto.Signer, intermediateSubject pkix.Name, subjectKeyID []byte, numIntermediates int, dirToSaveRoot string) *chain {
	if numIntermediates <= 0 {
		panic("At least one intermediate must be present in the certificate chain")
	}

	chainID := hex.EncodeToString(makeSerial().Bytes()[:3])

	root, err := ca.newRootIssuer(chainID)
	if err != nil {
		panic(fmt.Sprintf("Error creating new root issuer: %s", err.Error()))
	}

	if dirToSaveRoot != "" {
		certOut, err := os.Create(dirToSaveRoot + "/root_ca_pebble.pem")
		if err != nil {
			log.Fatalf("Failed to open cert.pem for writing: %v", err)
		}
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: root.cert.DER}); err != nil {
			log.Fatalf("Failed to write data to cert.pem: %v", err)
		}
		if err := certOut.Close(); err != nil {
			log.Fatalf("Error closing cert.pem: %v", err)
		}	
	}	

	// The last N-1 intermediates build a path from the root to the leaf signing certificate.
	// If numIntermediates is only 1, then no intermediates will be generated here.
	prev := root
	intermediates := make([]*issuer, numIntermediates)
	for i := numIntermediates - 1; i > 0; i-- {
		k, ski, err := makeKey()
		if err != nil {
			panic(fmt.Sprintf("Error creating new intermediate issuer: %v", err))
		}
		intermediate, err := ca.newIntermediateIssuer(prev, k, pkix.Name{
			CommonName: fmt.Sprintf("%s%s #%d", intermediateCAPrefix, chainID, i),
		}, ski)
		if err != nil {
			panic(fmt.Sprintf("Error creating new intermediate issuer: %s", err.Error()))
		}
		intermediates[i] = intermediate
		prev = intermediate
	}

	// The first issuer is the one which signs the leaf certificates
	intermediate, err := ca.newIntermediateIssuer(prev, intermediateKey, intermediateSubject, subjectKeyID)
	if err != nil {
		panic(fmt.Sprintf("Error creating new intermediate issuer: %s", err.Error()))
	}
	intermediates[0] = intermediate

	wrappeds := make([]*issuer, 0)

	c := &chain{
		root:          root,
		intermediates: intermediates,
		wrapped:       wrappeds,
	}
	ca.log.Printf("Generated issuance chain: %s", c)

	return c
}

func (ca *CAImpl) newCertificate(domains []string, ips []net.IP, key crypto.PublicKey, accountID, notBefore, notAfter string) (*core.Certificate, error) {
	var cn string
	if len(domains) > 0 {
		cn = domains[0]
	} else if len(ips) > 0 {
		cn = ips[0].String()
	} else {
		return nil, fmt.Errorf("must specify at least one domain name or IP address")
	}

	var defaultChain []*issuer
	if _, ok := key.(*wrap.PublicKey); ok {
		defaultChain = ca.chains[0].wrapped
	} else {
		defaultChain = ca.chains[0].intermediates
	}

	if len(defaultChain) == 0 || defaultChain[0].cert == nil {
		return nil, fmt.Errorf("cannot sign certificate - nil issuer")
	}
	issuer := defaultChain[0]

	subjectKeyID, err := makeSubjectKeyID(key)
	if err != nil {
		return nil, fmt.Errorf("cannot create subject key ID: %s", err.Error())
	}

	certNotBefore := time.Now()
	if notBefore != "" {
		certNotBefore, err = time.Parse(time.RFC3339, notBefore)
		if err != nil {
			return nil, fmt.Errorf("cannot parse Not Before date: %w", err)
		}
	}

	certNotAfter := certNotBefore.Add(time.Duration(ca.certValidityPeriod-1) * time.Second)
	maxNotAfter := time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	if certNotAfter.After(maxNotAfter) {
		certNotAfter = maxNotAfter
	}
	if notAfter != "" {
		certNotAfter, err = time.Parse(time.RFC3339, notAfter)
		if err != nil {
			return nil, fmt.Errorf("cannot parse Not After date: %w", err)
		}
	}

	serial := makeSerial()
	template := &x509.Certificate{
		DNSNames:    domains,
		IPAddresses: ips,
		Subject: pkix.Name{
			CommonName: cn,
		},
		SerialNumber: serial,
		NotBefore:    certNotBefore,
		NotAfter:     certNotAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SubjectKeyId:          subjectKeyID,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ca.ocspResponderURL != "" {
		template.OCSPServer = []string{ca.ocspResponderURL}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert.Cert, key, issuer.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	issuers := make([][]*core.Certificate, len(ca.chains))
	for i := 0; i < len(ca.chains); i++ {
		issuerChain := make([]*core.Certificate, len(ca.chains[i].wrapped) + len(ca.chains[i].intermediates))

		for j, cert := range ca.chains[i].wrapped {
			issuerChain[j] = cert.cert
		}

		wrappedChainLen := len(ca.chains[i].wrapped)

		for j, cert := range ca.chains[i].intermediates {
			issuerChain[wrappedChainLen + j] = cert.cert
		}
		issuers[i] = issuerChain
	}

	hexSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
	newCert := &core.Certificate{
		ID:           hexSerial,
		AccountID:    accountID,
		Cert:         cert,
		DER:          der,
		IssuerChains: issuers,
	}
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, err
	}
	return newCert, nil
}

func New(log *log.Logger, db *db.MemoryStore, ocspResponderURL string, alternateRoots int, chainLength int, certificateValidityPeriod uint, dirToSaveRoot string) *CAImpl {
	ca := &CAImpl{
		log:                log,
		db:                 db,
		certValidityPeriod: defaultValidityPeriod,
	}

	if ocspResponderURL != "" {
		ca.ocspResponderURL = ocspResponderURL
		ca.log.Printf("Setting OCSP responder URL for issued certificates to %q", ca.ocspResponderURL)
	}

	intermediateSubject := pkix.Name{
		CommonName: intermediateCAPrefix + hex.EncodeToString(makeSerial().Bytes()[:3]),
	}
	
	// intermediateKey, subjectKeyID, err := makeKey()
	intermediateKey, subjectKeyID, err := makeECDSAKey(3)

	if err != nil {
		panic(fmt.Sprintf("Error creating new intermediate private key: %s", err.Error()))
	}
	ca.chains = make([]*chain, 1+alternateRoots)
	for i := 0; i < len(ca.chains); i++ {
		ca.chains[i] = ca.newChain(intermediateKey, intermediateSubject, subjectKeyID, chainLength, dirToSaveRoot)
	}

	if certificateValidityPeriod != 0 && certificateValidityPeriod < 9223372038 {
		ca.certValidityPeriod = certificateValidityPeriod
	}

	ca.log.Printf("Using certificate validity period of %d seconds", ca.certValidityPeriod)

	return ca
}

func (ca *CAImpl) CompleteOrder(order *core.Order) {
	// Lock the order for reading
	order.RLock()
	// If the order isn't set as beganProcessing produce an error and immediately unlock
	if !order.BeganProcessing {
		ca.log.Printf("Error: Asked to complete order %s which had false beganProcessing.",
			order.ID)
		order.RUnlock()
		return
	}
	// Unlock the order again
	order.RUnlock()

	// Check the authorizations - this is done by the VA before calling
	// CompleteOrder but we do it again for robustness sake.
	for _, authz := range order.AuthorizationObjects {
		// Lock the authorization for reading
		authz.RLock()
		if authz.Status != acme.StatusValid {
			return
		}
		authz.RUnlock()
	}

	// issue a certificate for the csr
	csr := order.ParsedCSR

	if csr.PublicKeyAlgorithm == x509.AES256ECDSA {

		fmt.Printf("\nPebble: Received a CSR with a wrapped public key. Unwrapping the public key and verifying the CSR signature\n\n")

		ok, err := x509.VerifyWrappedCSRSignature(csr)
		if err != nil {
			panic(err)
		}
		
		if !ok {
			panic("Wrapped CSR signature is not valid")
		}

		fmt.Printf("Pebble: Wrapped CSR signature is valid.\n\nGenerating a new Issuer CA with a wrapped certificate\n\n")

		// Get cert psk 
		certPSK := x509.GetCertPSK(csr)

		// Generate a new wrapped Issuer
		chain := ca.getChain(0)
		ca.GenWrappedIssuer(chain, certPSK)
	}
	
	cert, err := ca.newCertificate(csr.DNSNames, csr.IPAddresses, csr.PublicKey, order.AccountID, order.NotBefore, order.NotAfter)
	if err != nil {
		ca.log.Printf("Error: unable to issue order: %s", err.Error())
		return
	}
	ca.log.Printf("Issued certificate serial %s for order %s\n", cert.ID, order.ID)

	// Lock and update the order to store the issued certificate
	order.Lock()
	order.CertificateObject = cert
	order.Unlock()
}

func (ca *CAImpl) GetNumberOfRootCerts() int {
	return len(ca.chains)
}

func (ca *CAImpl) getChain(no int) *chain {
	if 0 <= no && no < len(ca.chains) {
		return ca.chains[no]
	}
	return nil
}

func (ca *CAImpl) GetRootCert(no int) *core.Certificate {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}
	return chain.root.cert
}

func (ca *CAImpl) GetRootKey(no int) interface{} {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}

	switch key := chain.root.key.(type) {
	case *rsa.PrivateKey:
		return key
	
	case *liboqs_sig.PrivateKey:
		return key
	}
	return nil
}

// GetIntermediateCert returns the first (closest the the leaf) issuer certificate
// in the chain identified by `no`.
func (ca *CAImpl) GetIntermediateCert(no int) *core.Certificate {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}
	return chain.intermediates[0].cert
}

func (ca *CAImpl) GetIntermediateKey(no int) interface{} {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}

	switch key := chain.intermediates[0].key.(type) {
	case *rsa.PrivateKey:
		return key
		
	case *liboqs_sig.PrivateKey:
		return key

	}
	return nil
}

// Adds new wrapped issuer in the chain identified by `c`.
func (ca *CAImpl) GenWrappedIssuer(c *chain, psk []byte) {

	chainID := hex.EncodeToString(makeSerial().Bytes()[:3])
	parent := c.intermediates[0]
	// sigScheme := c.sigSchemeWrap

	// k, ski, err := makeKey()
	k, ski, err := makeECDSAKey(3)

	if err != nil {
		panic(fmt.Sprintf("Error creating new wrapped issuer: %v", err))
	}

	wrapped, err := ca.newWrappedIssuer(parent, k, pkix.Name{
		CommonName: fmt.Sprintf("%s%v", interWrappedCAPrefix, chainID),
	}, ski, psk)
	if err != nil {
		panic(fmt.Sprintf("Error creating new intermediate issuer: %s", err.Error()))
	}

	c.wrapped = append(c.wrapped, wrapped)

	n := len(c.wrapped)
	names := make([]string, n)
	for i := range c.wrapped {
		names[n-i-1] = c.wrapped[i].cert.Cert.Subject.CommonName
	}
	// w := strings.Join(names, ", ")

	// ca.log.Printf("Generated issuance chain: %s", c)

	fmt.Printf("\nPebble: Generated issuance chain: %s -> %s -> %s\n\n", c.root.cert.Cert.Subject.CommonName, c.intermediates[0].cert.Cert.Subject.CommonName, c.wrapped[0].cert.Cert.Subject.CommonName)
}