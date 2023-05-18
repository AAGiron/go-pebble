package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/liboqs_sig"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
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
	"github.com/letsencrypt/pebble/v2/ocsp"
)

// Prefix names used for certificates
const (
	rootCAPrefix            = "Pebble Root CA "
	intermediateCAPrefix    = "Pebble Intermediate CA "
	defaultValidityPeriod = 157766400
)

var (
	// RootSig is the name of the signature algorithm used by the Root CA
	RootSig string
	// InterSig is the name of the signature algorithm used by the Intermediate CAs
	InterSig string
	// IssuerSig is the name of the signature algorithm used by the Issuer CA
	IssuerSig string
	// TimingCSVPath is the path to the file where timing measurements are written to.
	TimingCSVPath string
	// OCSPResponseFilePath is the path to the file where the dummy OCSP response that is created is going to be written to.
	OCSPResponseFilePath string
	// ocspResponse is the dummy OCSP response that is created.
	ocspResponse []byte
)

type CAImpl struct {
	log              *log.Logger
	db               *db.MemoryStore
	ocspResponderURL string

	// ClassicChains contains all classical chains. 
	ClassicChains []*chain
	// PQCACME is set to true when a post-quantum chain is used
	PQCACME bool
	// PQChains contains all post-quantum chains.
	PQChains []*chain
	certValidityPeriod uint
}

type chain struct {
	Root          *issuer
	Intermediates []*issuer
}

func (c *chain) String() string {
	fullchain := append(c.Intermediates, c.Root)
	n := len(fullchain)

	names := make([]string, n)
	for i := range fullchain {
		names[n-i-1] = fullchain[i].Cert.Cert.Subject.CommonName
	}
	return strings.Join(names, " -> ")
}

type issuer struct {
	key  crypto.Signer
	Cert *core.Certificate
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

func makeKey(classicAlgorithm string) (crypto.Signer, []byte, error) {
	var key crypto.Signer 
	var ski []byte
	var err error
	
	switch classicAlgorithm {
	case "ECDSA-P256", "ECDSA-P384", "ECDSA-P521":
		key, ski, err = makeECDSAKey(classicAlgorithm)
	case "RSA-2048", "RSA-4096":
		key, ski, err = makeRSAKey(classicAlgorithm)
	}
	return key, ski, err
}

// makeKey and makeRootCert are adapted from MiniCA:
// https://github.com/jsha/minica/blob/3a621c05b61fa1c24bcb42fbde4b261db504a74f/main.go

// makeKey creates a new 2048 bit RSA private key and a Subject Key Identifier
func makeRSAKey(classicAlgorithm string) (*rsa.PrivateKey, []byte, error) {
	var key *rsa.PrivateKey
	var err error
	switch classicAlgorithm {
	case "RSA-2048":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "RSA-4096":
		key, err = rsa.GenerateKey(rand.Reader, 4096)

	}
	if err != nil {
		return nil, nil, err
	}
	ski, err := makeSubjectKeyID(key.Public())
	if err != nil {
		return nil, nil, err
	}
	return key, ski, nil
}

// makeECDSAKey generates an ECDSA private key for the algorithm with name `classicAlgorithm
func makeECDSAKey(classicAlgorithm string) (*ecdsa.PrivateKey, []byte, error) {
	var curve elliptic.Curve
	switch classicAlgorithm {
	case "ECDSA-P256":
		curve = elliptic.P256()
	case "ECDSA-P384":
		curve = elliptic.P384()
	case "ECDSA-P521":
		curve = elliptic.P521()
	default:
		panic(fmt.Sprintf("unknown classic algorithm: %s", classicAlgorithm))
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
	if signer != nil && signer.key != nil && signer.Cert != nil && signer.Cert.Cert != nil {
		signerKey = signer.key
		parent = signer.Cert.Cert
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
	if signer != nil && signer.Cert != nil {
		newCert.IssuerChains = make([][]*core.Certificate, 1)
		newCert.IssuerChains[0] = []*core.Certificate{signer.Cert}
	}
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, err
	}
	return newCert, nil
}

func (ca *CAImpl) newRootIssuer(name string) (*issuer, error) {
	// Make a root private key
	rk, subjectKeyID, err := makeKey(RootSig)
	
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
		Cert: rc,
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
		Cert: ic,
	}, nil
}

// newChain generates a new issuance chain, including a root certificate and numIntermediates intermediates (at least 1).
// The first intermediate will use intermediateKey, intermediateSubject and subjectKeyId.
// Any intermediates between the first intermediate and the root will have their keys and subjects generated automatically.

// PQCACME Modification: after the root CA is generated, we write it's certificate to `dirToSaveRoot`. Without this modification,
// the root CA would not be persisted and the TLS client of our tests would not be able to trust in it.
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
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: root.Cert.DER}); err != nil {
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
		k, ski, err := makeKey(InterSig)
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

	c := &chain{
		Root:          root,
		Intermediates: intermediates,
	}
	ca.log.Printf("Generated issuance chain: %s", c)

	return c
}

// newCertificate
// PQCACME Modification: Dummy Signed Certificate Timestamps are now attached to the certificate generated and 
// a dummy OCSP Response is created. Both the SCT and OCSP Response are signed by `issuer`.
func (ca *CAImpl) newCertificate(domains []string, ips []net.IP, key crypto.PublicKey, accountID, notBefore, notAfter string) (*core.Certificate, error) {
// newChain generates a new issuance chain, including a root certificate and numIntermediates intermediates (at least 1).
// The first intermediate will use intermediateKey, intermediateSubject and subjectKeyId.
// Any intermediates between the first intermediate and the root will have their keys and subjects generated automatically.

	var cn string
	if len(domains) > 0 {
		cn = domains[0]
	} else if len(ips) > 0 {
		cn = ips[0].String()
	} else {
		return nil, fmt.Errorf("must specify at least one domain name or IP address")
	}

	
	var defaultChain []*issuer
	if !ca.PQCACME {
		defaultChain = ca.ClassicChains[0].Intermediates
	} else {
		defaultChain = ca.PQChains[0].Intermediates
	}
	

	if len(defaultChain) == 0 || defaultChain[0].Cert == nil {
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

	sctExt, err := x509.CreateSCT(rand.Reader, template, issuer.Cert.Cert, key, issuer.key)
	if err != nil {
		return nil, err
	}

	if OCSPResponseFilePath != "" {
		ocspResponse, _ = ocsp.CreateOCSPResponse(rand.Reader, issuer.Cert.Cert, issuer.key)
	}

	template.ExtraExtensions = []pkix.Extension{sctExt}	

	der, err := x509.CreateCertificate(rand.Reader, template, issuer.Cert.Cert, key, issuer.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	var Chains []*chain
	if !ca.PQCACME {
		Chains = ca.ClassicChains
	} else {
		Chains = ca.PQChains
	}
	issuers := make([][]*core.Certificate, len(Chains))
	for i := 0; i < len(Chains); i++ {			
		issuerChain := make([]*core.Certificate, len(Chains[i].Intermediates))
		for j, cert := range Chains[i].Intermediates {
			issuerChain[j] = cert.Cert
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

func New(log *log.Logger, db *db.MemoryStore, ocspResponderURL string, alternateRoots int, chainLength int, certificateValidityPeriod uint, dirToSaveRoot string, pqChain []string, hybrid bool) *CAImpl {
	ca := &CAImpl{
		log:                log,
		db:                 db,
		certValidityPeriod: defaultValidityPeriod,
	}

	if ocspResponderURL != "" {
		ca.ocspResponderURL = ocspResponderURL
		ca.log.Printf("Setting OCSP responder URL for issued certificates to %q", ca.ocspResponderURL)
	}

	// Now is possible to generate two types of chain
	// A) classical chain (using ECDSA) 
	// B) hybrid and pq-only chain

	// case A)
	if pqChain[0] == "" {
		ca.PQCACME = false

		intermediateSubject := pkix.Name{
			CommonName: intermediateCAPrefix + hex.EncodeToString(makeSerial().Bytes()[:3]),
		}

		intermediateKey, subjectKeyID, err := makeKey(InterSig)

		if err != nil {
			panic(fmt.Sprintf("Error creating new intermediate private key: %s", err.Error()))
		}
		ca.ClassicChains = make([]*chain, 1+alternateRoots)
		for i := 0; i < len(ca.ClassicChains); i++ {
			ca.ClassicChains[i] = ca.newChain(intermediateKey, intermediateSubject, subjectKeyID, chainLength, dirToSaveRoot)
		}
	
	// Case B)
	} else {
		ca.PQCACME = true
		ca.AddPQChain(chainLength, dirToSaveRoot, pqChain, hybrid)
	}

	if certificateValidityPeriod != 0 && certificateValidityPeriod < 9223372038 {
		ca.certValidityPeriod = certificateValidityPeriod
	}

	ca.log.Printf("Using certificate validity period of %d seconds", ca.certValidityPeriod)

	return ca
}

// It was added code to measure the time elapsed to process the CSR and issue a certificate for it.
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
	
	timer := time.Now
	start := timer()		

	if err := csr.CheckSignature(); err != nil {
		ca.log.Printf("Error: unable to verify regular CSR : %s", err.Error())
		return 
	}

	cert, err := ca.newCertificate(csr.DNSNames, csr.IPAddresses, csr.PublicKey, order.AccountID, order.NotBefore, order.NotAfter)
	if err != nil {
		ca.log.Printf("Error: unable to issue order: %s", err.Error())
		return
	}

	elapsedTime := timer().Sub(start)	
	if TimingCSVPath != "" {
		writeElapsedTime(float64(elapsedTime)/float64(time.Millisecond), cert.Cert.PublicKey, cert.Cert.SignatureAlgorithm.String())
	}
	
	if ocspResponse != nil && OCSPResponseFilePath != "" {
		err = os.WriteFile(OCSPResponseFilePath, ocspResponse, 0644)
		if err != nil {
			panic(err)
		}
	}

	ca.log.Printf("Issued certificate serial %s for order %s\n", cert.ID, order.ID)

	// Lock and update the order to store the issued certificate
	order.Lock()
	order.CertificateObject = cert
	order.Unlock()
}

func (ca *CAImpl) GetNumberOfRootCerts() int {
	return len(ca.ClassicChains)
}

func (ca *CAImpl) getChain(no int) *chain {
	if 0 <= no && no < len(ca.ClassicChains) {
		return ca.ClassicChains[no]
	}
	return nil
}


func (ca *CAImpl) GetRootCert(no int) *core.Certificate {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}
	return chain.Root.Cert
}

func (ca *CAImpl) GetRootKey(no int) interface{} {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}

	switch key := chain.Root.key.(type) {
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
	return chain.Intermediates[0].Cert
}
// GetIntermediateKey returns the private key of the first (closest to the leaf) issuer CA
// in the chain identified by `no`.
func (ca *CAImpl) GetIntermediateKey(no int) interface{} {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}
	switch key := chain.Intermediates[0].key.(type) {
	case *rsa.PrivateKey:
		return key
		
	case *liboqs_sig.PrivateKey:
		return key

	}
	return nil
}

// writeElapsedTime writes the elapsed time to Pebble process a CSR and issue a certificate for it in the file pointed by `TimingCSVPath`.
func writeElapsedTime(elapsedTime float64, certificatePublicKey interface{}, signatureAlgorithm string) {
	var toWrite []string
	certAlgorithm := getPublicKeyAlgorithmName(certificatePublicKey)	

	csvFile, err := os.OpenFile(TimingCSVPath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	
	csvwriter := csv.NewWriter(csvFile)
	csvReader := csv.NewReader(csvFile)
	_, err = csvReader.Read()
	if err == io.EOF {
		toWrite = []string{"Certificate Public Key Algorithm", "Certificate Signature Algorithm", "/finalize-order/ endpoint issuance time (ms)"}
		if err := csvwriter.Write(toWrite); err != nil {
			log.Fatalf("error writing record to file. err: %s", err)
		}
	}

	toWrite = []string{certAlgorithm, signatureAlgorithm, fmt.Sprintf("%f", elapsedTime)}
	
	if err := csvwriter.Write(toWrite); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	
	csvwriter.Flush()
	csvFile.Close()
}

func getPublicKeyAlgorithmName(publicKey interface{}) string {	
	pqcPub, ok := publicKey.(*liboqs_sig.PublicKey)
	if ok {
		return liboqs_sig.SigIdtoName[pqcPub.SigId]
	}

	ecPub, ok := publicKey.(*ecdsa.PublicKey)
	if ok {
		var ellipticCurve string
	
		switch ecPub.Curve {
		case elliptic.P256():
			ellipticCurve = "P256"
		case elliptic.P384():
			ellipticCurve = "P384"
		case elliptic.P521():
			ellipticCurve = "P521"
		default:
			ellipticCurve = "Unknown"
		}		
		return "ECDSA_" + ellipticCurve
	}
	return ""
}