package main
//we should create a package for the newchallenge.


import (
	"net/http"
	"fmt"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	//"encoding/pem"
	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/core"
	"net"
	"strings"
	"sort"
	"bytes"
	"crypto/rand"
	"io"
	"time"
)


//store a PQOrder in the DB. Follows wfe.go and memorystore.go
func storePQOrder(rw http.ResponseWriter, orderID string, 
					csrDNSs []string, csrIPs []net.IP,
					accountID string, parsedCSR *x509.CertificateRequest) (*core.Order){
	grabbedWFE := *GlobalWebFrontEnd

	//populate not after and notBefore from CSR? In newOrder

	//change unique names to acme.identifier object
	var uniquenames []acme.Identifier
	for _, name := range csrDNSs {
		uniquenames = append(uniquenames, acme.Identifier{Value: name, Type: acme.IdentifierDNS})
	}
	for _, ip := range csrIPs {
		uniquenames = append(uniquenames, acme.Identifier{Value: ip.String(), Type: acme.IdentifierIP})
	}

	expires := time.Now().AddDate(0, 0, 1) 
	//maybe this could be checked in the future (new() instead of pointing to the struct)	
	order := &core.Order{
		ID:        		 orderID,
		AccountID: 		 accountID,
		Order: acme.Order{
			Status:  	 acme.StatusValid,
			Expires: 	 expires.UTC().Format(time.RFC3339),
			Identifiers: uniquenames,
			NotBefore:   time.Now().String(),
			NotAfter:    time.Now().AddDate(0, 0, 90).String(), //let's encrypt example
		},
		ExpiresDate: 	 expires,
		BeganProcessing: true, //need this in ca.go CompleteOrder
		ParsedCSR: 		 parsedCSR,
		//AuthorizationObjects: []*Authorization hope that range order.AuthorizationObjects returns 0 in ca.go
	}

	//Add order to the WFE db
	count, err := grabbedWFE.Db.AddOrder(order)
	if err != nil {
		grabbedWFE.SendError(
			acme.InternalErrorProblem("Error saving order"), rw)
		return nil
	}
	grabbedWFE.Log.Printf("Added order %q to the db\n", order.ID)
	grabbedWFE.Log.Printf("There are now %d orders in the db\n", count)
	return order
}

//wrapper to call issuance from ca.go
func issuePQCert(order *core.Order){
	grabbedWFE := *GlobalWebFrontEnd

	//calls ca.go's Complete Order using go routine
	go grabbedWFE.Ca.CompleteOrder(order) 
}

//This function depends on GlobalWebFrontEnd variable (main.go)
func HandlePQOrder(rw http.ResponseWriter, req *http.Request){
	
	if GlobalWebFrontEnd == nil {
		fmt.Fprint( rw, "No access to WFE and CA information... :(\n" )
		return
	}

	grabbedWFE := *GlobalWebFrontEnd //conteudo de pointer?

	//1. Parse request
	//parses JWS in the request, retrieves account Pk (if found) and verifies the signature
	postData, prob := grabbedWFE.VerifyPOST(req, grabbedWFE.LookupJWK)
	if prob != nil {
		grabbedWFE.SendError(prob, rw)
		return
	}
	

	//2. There is no order (yet), so go straight parsing and processing CSR 
	//to issue a PQ certificate
	var finalizeMessage struct {
		CSR string
	}
	//might throw an error here: our finalize has more things in the body
	err := json.Unmarshal(postData.Body, &finalizeMessage)
	if err != nil {
		grabbedWFE.SendError(acme.MalformedProblem(fmt.Sprintf(
			"Error unmarshaling finalize order request body: %s", err.Error())), rw)
		return
	}

	csrBytes, err := base64.RawURLEncoding.DecodeString(finalizeMessage.CSR)
	if err != nil {
		grabbedWFE.SendError(
			acme.MalformedProblem("Error decoding Base64url-encoded CSR: "+err.Error()), rw)
		return
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		grabbedWFE.SendError(
			acme.MalformedProblem("Error parsing Base64url-encoded CSR: "+err.Error()), rw)
		return
	}

	//3. TODO: check if the TLS client certificate domain name 
	//matches the domain asked in the CSR
	
	////////////////////////////////////////////////////////////////////////////////
	//we can get csr info, but the TLS-layer certificate is not here... it's something like AJP protocol	
	csrDNSs := UniqueLowerNames(parsedCSR.DNSNames)
	csrIPs := UniqueIPs(parsedCSR.IPAddresses)

	// No account key signing RFC8555 Section 11.1 (same from wfe.go)
	existsAcctForCSRKey, _ := grabbedWFE.GetAcctByKey(parsedCSR.PublicKey)
	if existsAcctForCSRKey != nil {
		grabbedWFE.SendError(acme.BadCSRProblem("CSR contains a public key for a known account"), rw)
		return
	}

	//4. Store a new order directly
	orderID := randomString(32) //same as newToken()
	//First call this because we need the ID to store the order.
	existingAcct, prob := grabbedWFE.GetAcctByKey(postData.Jwk)
	if prob != nil {
		grabbedWFE.SendError(prob, rw)
		return
	}
	//store the valid order in the DB.
	existingOrder := storePQOrder(rw, orderID,csrDNSs, csrIPs, existingAcct.ID, parsedCSR)
	if existingOrder == nil {
		grabbedWFE.SendError(acme.InternalErrorProblem("Error saving order"), rw)
		return 
	}

	//log that so far so good
	grabbedWFE.Log.Printf("Request for %s is fully authorized. Issuing certificate...", existingAcct)

	//5. Issue the certificate (CompleteOrder(existingOrder))
	existingOrder.Status = acme.StatusValid
	issuePQCert(existingOrder)

	//Prepare the order for display as JSON
	//6. and create URL for download.
	orderReq := grabbedWFE.OrderForDisplay(existingOrder, req)	      //export orderPath //in wfe?
	orderURL := grabbedWFE.RelativeEndpoint(req, fmt.Sprintf("%s%s", "/my-order/", existingOrder.ID))
	rw.Header().Add("Location", orderURL)
	err = grabbedWFE.WriteJSONResponse(rw, http.StatusOK, orderReq)
	if err != nil {
		grabbedWFE.SendError(acme.InternalErrorProblem("Error marshaling order"), rw)
		return
	}

}



/*copied from wfe: two functions below
*/
// UniqueLowerNames returns the set of all unique names in the input after all
// of them are lowercased. The returned names will be in their lowercased form
// and sorted alphabetically. See Boulder `core/util.go UniqueLowerNames`.
func UniqueLowerNames(names []string) []string {
	nameMap := make(map[string]int, len(names))
	for _, name := range names {
		nameMap[strings.ToLower(name)] = 1
	}
	unique := make([]string, 0, len(nameMap))
	for name := range nameMap {
		unique = append(unique, name)
	}
	sort.Strings(unique)
	return unique
}

// UniqueIPs returns the set of all unique IP addresses in the input.
// The returned IP addresses will be sorted in ascending order in text form.
func UniqueIPs(IPs []net.IP) []net.IP {
	uniqMap := make(map[string]net.IP)
	for _, ip := range IPs {
		uniqMap[ip.String()] = ip
	}
	results := make([]net.IP, 0, len(uniqMap))
	for _, v := range uniqMap {
		results = append(results, v)
	}
	sort.Slice(results, func(i, j int) bool {
		return bytes.Compare(results[i], results[j]) < 0
	})
	return results
}


//from wfe/token.go
func randomString(byteLength int) string {
	b := make([]byte, byteLength)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(fmt.Sprintf("Error reading random bytes: %s", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
