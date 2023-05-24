package newchallenge

import (
	"crypto/x509"
	"encoding/base64"

	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/wfe"
	"gopkg.in/square/go-jose.v2"
)

type NewChallengeWFE struct {
	wfe.WebFrontEndImpl
}

// PQCACME Modification: storePQOrder store a pq-order in the DB. 
func (w *NewChallengeWFE) storePQOrder(rw http.ResponseWriter, orderID string, 
					csrDNSs []string, csrIPs []net.IP,
					accountID string, parsedCSR *x509.CertificateRequest) (*core.Order){

	// Change unique names to acme.identifier object
	var uniquenames []acme.Identifier
	for _, name := range csrDNSs {
		uniquenames = append(uniquenames, acme.Identifier{Value: name, Type: acme.IdentifierDNS})
	}
	for _, ip := range csrIPs {
		uniquenames = append(uniquenames, acme.Identifier{Value: ip.String(), Type: acme.IdentifierIP})
	}

	expires := time.Now().AddDate(0, 0, 1) 
	order := &core.Order{
		ID:        		 orderID,
		AccountID: 		 accountID,
		Order: acme.Order{
			Status:  	 acme.StatusValid,
			Expires: 	 expires.UTC().Format(time.RFC3339),
			Identifiers: uniquenames,
			NotBefore:   time.Now().Format(time.RFC3339),
			NotAfter:    time.Now().AddDate(0, 0, 90).Format(time.RFC3339), 
		},
		ExpiresDate: 	 expires,
		BeganProcessing: true,
		ParsedCSR: 		 parsedCSR,
	}

	// Add order to the WFE db
	count, err := w.Db.AddOrder(order)
	if err != nil {
		w.SendError(
			acme.InternalErrorProblem("Error saving order"), rw)
		return nil
	}
	w.Log.Printf("Added order %q to the db\n", order.ID)
	w.Log.Printf("There are now %d orders in the db\n", count)
	return order
}

// PQCACME Modification: Entry point to our new challenge work properly.
func (w *NewChallengeWFE) HandlePQOrder(rw http.ResponseWriter, req *http.Request){

	
	//1. Parse request	
	w.Log.Printf("Verifying a POST received at /pq-order...")
	// Parses JWS in the request, retrieves account Pk (if found) and verifies the signature
	postData, prob := w.VerifyPOST(req, w.LookupJWK)
	if prob != nil {
		w.SendError(prob, rw)
		return
	}

	//2. There is no order (yet), so go straight parsing and processing CSR to issue a PQ certificate
	var finalizeMessage struct {
		CSR string
	}

	err := json.Unmarshal(postData.Body, &finalizeMessage)
	if err != nil {
		w.SendError(acme.MalformedProblem(fmt.Sprintf(
			"Error unmarshaling finalize order request body: %s", err.Error())), rw)
		return
	}

	csrBytes, err := base64.RawURLEncoding.DecodeString(finalizeMessage.CSR)
	if err != nil {
		w.SendError(
			acme.MalformedProblem("Error decoding Base64url-encoded CSR: "+err.Error()), rw)
		return
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		w.SendError(
			acme.MalformedProblem("Error parsing Base64url-encoded CSR: "+err.Error()), rw)
		return
	}

	// Set pebble to use post-quantum PKI to issue the certificate
	if (jose.StringIsLiboqs(parsedCSR.SignatureAlgorithm.String()) != "") {
		w.Ca.PQCACME = true
	}
	

	csrDNSs := wfe.UniqueLowerNames(parsedCSR.DNSNames)
	csrIPs := wfe.UniqueIPs(parsedCSR.IPAddresses)

	//3. Check if the TLS-layer client certificate domain name matches the domain asked in the CSR 		
	if ! (req.TLS.PeerCertificates[0].Subject.CommonName == csrDNSs[0]) {
		fmt.Fprint(rw, "TLS client certificate common name does not match the requested CSR name.\n")
		return
	}

	// No account key signing RFC8555 Section 11.1 (same from wfe.go)
	existsAcctForCSRKey, _ := w.GetAcctByKey(parsedCSR.PublicKey)
	if existsAcctForCSRKey != nil {
		w.SendError(acme.BadCSRProblem("CSR contains a public key for a known account"), rw)
		return
	}

	// 4. Store a new order directly
	orderID := wfe.RandomString(32)
	
	// Get the ID to store the order
	existingAcct, prob := w.GetAcctByKey(postData.Jwk)
	if prob != nil {
		w.SendError(prob, rw)
		return
	}
	
	// Store the valid order in the DB.
	existingOrder := w.storePQOrder(rw, orderID,csrDNSs, csrIPs, existingAcct.ID, parsedCSR)
	if existingOrder == nil {
		w.SendError(acme.InternalErrorProblem("Error saving order"), rw)
		return 
	}

	w.Log.Printf("Request for %s is fully authorized. Issuing certificate...", existingAcct.ID)

	//5. Issue the certificate 
	existingOrder.Status = acme.StatusValid
	w.Ca.CompleteOrder(existingOrder) 

	//6. Prepare the order for display as JSON and create URL for download.
	orderReq := w.OrderForDisplay(existingOrder, req)	         
	
	err = w.WriteJSONResponse(rw, http.StatusOK, orderReq)
	if err != nil {
		w.SendError(acme.InternalErrorProblem("Error marshaling order"), rw)
		return
	}

	// Reverts the CA back to the original one after new challenge was executed
	w.Ca.PQCACME = false
}