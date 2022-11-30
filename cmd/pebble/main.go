package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/cmd"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
)

type config struct {
	Pebble struct {
		ListenAddress           string
		ManagementListenAddress string
		HTTPPort                int
		TLSPort                 int
		Certificate             string
		PrivateKey              string
		OCSPResponderURL        string
		// Require External Account Binding for "newAccount" requests
		ExternalAccountBindingRequired bool
		ExternalAccountMACKeys         map[string]string
		// Configure policies to deny certain domains
		DomainBlocklist []string

		CertificateValidityPeriod uint
	}
}

func main() {
	configFile := flag.String(
		"config",
		"test/config/pebble-config.json",
		"File path to the Pebble configuration file")
	strictMode := flag.Bool(
		"strict",
		false,
		"Enable strict mode to test upcoming API breaking changes")
	resolverAddress := flag.String(
		"dnsserver",
		"",
		"Define a custom DNS server address (ex: 192.168.0.56:5053 or 8.8.8.8:53).")
	dirToSaveRoot := flag.String(
		"rootdir",
		"",
		"Path to the directory where the Pebble Root CA certificate will be written/saved")
	kex := flag.String(
		"kex",
		"",
		"Set the KEX algorithm to be used in the TLS connection")
	pqtls := flag.Bool(
		"pqtls",
		false,
		"By setting this flag to true, the ACME Server will launch a PQTLS server")
	hybrid := flag.Bool(
		"hybrid", 
		false,
		"By setting this flag to true, pebble will launch a hybrid chain",
	)
	rootSig := flag.String(
		"rootSig",
		"",
		"Set the Root CA signature scheme. Possible values: ECDSA-P256, ECDSA-P384, ECDSA-P521, dilithium2, dilihthium3, dilithium5, falcon512, falcon1024, sphincsshake128ssimple, sphincsshake256ssimple")

	interSig := flag.String(
		"interSig", 
		"", 
		"Set the Intermediate CA signature scheme. Possible values: ECDSA-P256, ECDSA-P384, ECDSA-P521, dilithium2, dilihthium3, dilithium5, falcon512, falcon1024, sphincsshake128ssimple, sphincsshake256ssimple",
	)
	issuerSig := flag.String(
		"issuerSig", 
		"",
		"Set the Issuer CA signature scheme. Possible values: ECDSA-P256, ECDSA-P384, ECDSA-P521, dilithium2, dilihthium3, dilithium5, falcon512, falcon1024, sphincsshake128ssimple, sphincsshake256ssimple",
	)
	
	timingsCSVPath := flag.String(
		"timingcsv",
		"",
		"Path to the CSV file where the timing metrics are written to")
	loadTestFinalize := flag.Bool(
		"loadtestfinalize",
		false,
		"By setting this flag to true, the ACME Server will allow the ACME Client to perform a load test in the /finalize-order/ endpoint")
	ocspResponseFilePath := flag.String(
		"ocspresponsepath",
		"",
		"Path to the file where the OCSP Response is written to")

	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	ca.TimingCSVPath = *timingsCSVPath
	ca.OCSPResponseFilePath = *ocspResponseFilePath
	wfe.LoadTestFinalize = *loadTestFinalize

	// Log to stdout
	logger := log.New(os.Stdout, "Pebble ", log.LstdFlags)
	logger.Printf("Starting Pebble ACME server")

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	alternateRoots := 0
	alternateRootsVal := os.Getenv("PEBBLE_ALTERNATE_ROOTS")
	if val, err := strconv.ParseInt(alternateRootsVal, 10, 0); err == nil && val >= 0 {
		alternateRoots = int(val)
	}

	chainLength := 1
	if val, err := strconv.ParseInt(os.Getenv("PEBBLE_CHAIN_LENGTH"), 10, 0); err == nil && val >= 0 {
		chainLength = int(val)
	}

	pqChain := []string{"", "", ""}
	ecdsaRegex := regexp.MustCompile(`ECDSA`)		
	
	if !ecdsaRegex.MatchString(*rootSig) && !ecdsaRegex.MatchString(*interSig) && !ecdsaRegex.MatchString(*issuerSig) {
		fmt.Println("PQCHAIN")
		pqChain = []string{*rootSig, *interSig, *issuerSig}			
	} else if ecdsaRegex.MatchString(*rootSig) && ecdsaRegex.MatchString(*interSig) && ecdsaRegex.MatchString(*issuerSig) {
		fmt.Println("CLASSIC CHAIN")
		ca.RootSig = *rootSig
		ca.InterSig = *interSig
		ca.IssuerSig = *issuerSig		
	} else {
		panic("mixing post-quantum and classic algorithms in CA chain is not allowed")
	}

	db := db.NewMemoryStore()
	ca := ca.New(logger, db, c.Pebble.OCSPResponderURL, alternateRoots, chainLength, c.Pebble.CertificateValidityPeriod, *dirToSaveRoot, pqChain, *hybrid)
	va := va.New(logger, c.Pebble.HTTPPort, c.Pebble.TLSPort, *strictMode, *resolverAddress)

	for keyID, key := range c.Pebble.ExternalAccountMACKeys {
		err := db.AddExternalAccountKeyByID(keyID, key)
		cmd.FailOnError(err, "Failed to add key to external account bindings")
	}

	for _, domainName := range c.Pebble.DomainBlocklist {
		err := db.AddBlockedDomain(domainName)
		cmd.FailOnError(err, "Failed to add domain to block list")
	}

	wfeImpl := wfe.New(logger, db, va, ca, *strictMode, c.Pebble.ExternalAccountBindingRequired)
	muxHandler := wfeImpl.Handler()

	if c.Pebble.ManagementListenAddress != "" {
		go func() {
			adminHandler := wfeImpl.ManagementHandler()
			err = http.ListenAndServeTLS(
				c.Pebble.ManagementListenAddress,
				c.Pebble.Certificate,
				c.Pebble.PrivateKey,
				adminHandler)
			cmd.FailOnError(err, "Calling ListenAndServeTLS() for admin interface")
		}()
		logger.Printf("Management interface listening on: %s\n", c.Pebble.ManagementListenAddress)
		logger.Printf("Root CA certificate available at: https://%s%s0",
			c.Pebble.ManagementListenAddress, wfe.RootCertPath)
		for i := 0; i < alternateRoots; i++ {
			logger.Printf("Alternate (%d) root CA certificate available at: https://%s%s%d",
				i+1, c.Pebble.ManagementListenAddress, wfe.RootCertPath, i+1)
		}
	} else {
		logger.Print("Management interface is disabled")
	}

	logger.Printf("Listening on: %s\n", c.Pebble.ListenAddress)
	logger.Printf("ACME directory available at: https://%s%s",
		c.Pebble.ListenAddress, wfe.DirectoryPath)
	
	if *pqtls {
		tlsCfg := &tls.Config {
			PQTLSEnabled: true,			
			IgnoreSigAlg: true,
		}
		curveID := tls.StringToCurveIDMap[*kex]
		if curveID != tls.CurveID(0) {
			tlsCfg.CurvePreferences = []tls.CurveID{curveID}
		}
		
		err = http.ListenAndServeTLSWithConfig(
			c.Pebble.ListenAddress,
			c.Pebble.Certificate,
			c.Pebble.PrivateKey,
			muxHandler,
			tlsCfg,
		)
	} else {
		err = http.ListenAndServeTLS(
			c.Pebble.ListenAddress,
			c.Pebble.Certificate,
			c.Pebble.PrivateKey,
			muxHandler,
		)
	}
	
	cmd.FailOnError(err, "Calling ListenAndServeTLS()")
}
