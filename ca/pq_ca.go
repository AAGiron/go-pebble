package ca

import (
	"crypto"
	"crypto/liboqs_sig"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// Prefix names used for certificates
const (
	pqRootCAPrefix          = "Pebble Post-quantum Root CA "
	pqIntermediateCAPrefix  = "Pebble Post-quantum Intermediate CA "
	hybridRootCAPrefix          = "Pebble Hybrid Root CA "
	hybridIntermediateCAPrefix  = "Pebble Hybrid Intermediate CA "
)


// Signatures schemes for local use
type pqcSignature int
const (

	unknownPQCsignature pqcSignature = iota
	
	Dilithium2 
	Falcon512  
	
	Dilithium3 	
	
	Dilithium5
	Falcon1024 

	SphincsShake128sSimple 
	SphincsShake256sSimple 

	P256_Dilithium2
	P256_Falcon512
	P256_SphincsShake128sSimple


	P384_Dilithium3

	P521_Dilithium5
	P521_Falcon1024
	P521_SphincsShake256sSimple
)

// makePQCKey generates a post-quantum private key for the algorithm with name `pqcAlgorithm`
func makePQCKey(pqcAlgorithm string) (*liboqs_sig.PrivateKey, []byte, error) {
	var ID liboqs_sig.ID

	ID = liboqs_sig.NameToSigID(pqcAlgorithm)
	
	pub, priv, err := liboqs_sig.GenerateKey(ID)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	ski, err := makeSubjectKeyID(pub)
	if err != nil {
		return nil, nil, err
	}
	return priv, ski, nil
}

// newPqRootIssuer creates a post-quantum Root CA by generating a post-quantum private key and issuing
// a self-signed CA certificate for it.
func (ca *CAImpl) newPqRootIssuer(name, rootSig string, hybrid bool) (*issuer, error) {
	
	// Make a root private key
	rk, subjectKeyID, err := makePQCKey(rootSig)
	if err != nil {
		return nil, err
	}

	// Make a self-signed root certificate
	var subject pkix.Name
	
	if !hybrid {
		subject = pkix.Name{
			CommonName: pqRootCAPrefix + name,
		}
	} else {
		subject = pkix.Name{
			CommonName: hybridRootCAPrefix + name,
		}
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


func (ca *CAImpl) newPqIntermediateIssuer(root *issuer, intermediateKey crypto.Signer, subject pkix.Name, subjectKeyID []byte, hybrid bool) (*issuer, error) {
	if root == nil {
		return nil, fmt.Errorf("Internal error: root must not be nil")
	}

	// Make an intermediate certificate with root signature
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

// PQCACME Modification: Adds `pqChain` as `ca.PQChains`
// It also suits for newchallenge when new post-quantum chain is required on the demand
func (ca *CAImpl) AddPQChain(chainLength int, dirToSaveRoot string, pqChain []string, hybrid bool) {
	ca.PQCACME = true
	var intermediateSubject pkix.Name
	
	if hybrid {
		intermediateSubject = pkix.Name{
			CommonName: hybridIntermediateCAPrefix + hex.EncodeToString(makeSerial().Bytes()[:3]),
		}
	} else {
		intermediateSubject = pkix.Name{
			CommonName: pqIntermediateCAPrefix + hex.EncodeToString(makeSerial().Bytes()[:3]),
		}
	}
	intermediateKey, subjectKeyID, err := makePQCKey(pqChain[2])
	if err != nil {
		panic(fmt.Sprintf("Error creating new intermediate private key: %s", err.Error()))
	}

	ca.PQChains = make([]*chain, 1)
	for i := 0; i < len(ca.PQChains); i++ {
		ca.PQChains[i] = ca.newPqChain(intermediateKey, intermediateSubject, subjectKeyID, chainLength, dirToSaveRoot, pqChain, hybrid)
	}
}

// PQCACME Modification: newPqChain generates a new post-quantum issuance chain, including a root certificate and numIntermediates intermediates (at least 1).
func (ca *CAImpl) newPqChain(intermediateKey crypto.Signer, intermediateSubject pkix.Name, subjectKeyID []byte, numIntermediates int, dirToSaveRoot string, pqChain []string, hybrid bool) *chain {
	if numIntermediates <= 0 {
		panic("At least one intermediate must be present in the certificate chain")
	}

	chainID := hex.EncodeToString(makeSerial().Bytes()[:3])

	root, err := ca.newPqRootIssuer(chainID, pqChain[0], hybrid)
	if err != nil {
		panic(fmt.Sprintf("Error creating new root issuer: %s", err.Error()))
	}

	if dirToSaveRoot != "" {
		var certOut *os.File

		if !hybrid {
			certOut, err = os.Create(dirToSaveRoot + "/pq_root_ca_pebble.pem")
		} else {
			certOut, err = os.Create(dirToSaveRoot + "/hybrid_root_ca_pebble.pem")
		}

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
		
		k, ski, err := makePQCKey(pqChain[1])

		if err != nil {
			panic(fmt.Sprintf("Error creating new intermediate issuer: %v", err))
		}

		var intermediate *issuer
		if hybrid {
			intermediate, err = ca.newPqIntermediateIssuer(prev, k, pkix.Name{
				CommonName: fmt.Sprintf("%s%s #%d", hybridIntermediateCAPrefix, chainID, i),
			}, ski, hybrid)
		} else {
			intermediate, err = ca.newPqIntermediateIssuer(prev, k, pkix.Name{
				CommonName: fmt.Sprintf("%s%s #%d", pqIntermediateCAPrefix, chainID, i),
			}, ski, hybrid)
		}
	
		if err != nil {
			panic(fmt.Sprintf("Error creating new intermediate issuer: %s", err.Error()))
		}
		intermediates[i] = intermediate
		prev = intermediate
	}

	// The first issuer is the one which signs the leaf certificates
	intermediate, err := ca.newPqIntermediateIssuer(prev, intermediateKey, intermediateSubject, subjectKeyID, hybrid)
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
