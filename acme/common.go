package acme

// acme.Resource values identify different types of ACME resources
type Resource string

const (
	StatusPending     = "pending"
	StatusInvalid     = "invalid"
	StatusValid       = "valid"
	StatusExpired     = "expired"
	StatusProcessing  = "processing"
	StatusReady       = "ready"
	StatusDeactivated = "deactivated"

	IdentifierDNS = "dns"
	IdentifierIP  = "ip"

	ChallengeHTTP01    = "http-01"
	ChallengeTLSALPN01 = "tls-alpn-01"
	ChallengeDNS01     = "dns-01"

	HTTP01BaseURL = ".well-known/acme-challenge/"

	ACMETLS1Protocol = "acme-tls/1"
)

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (ident Identifier) Equals(other Identifier) bool {
	return ident.Type == other.Type && ident.Value == other.Value
}

type JSONSigned struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Sig       string `json:"signature"`
}

type Account struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders,omitempty"`

	ExternalAccountBinding *JSONSigned `json:"externalAccountBinding,omitempty"`
}

// An Order is created to request issuance for a CSR
type Order struct {
	Status         string          `json:"status"`
	Error          *ProblemDetails `json:"error,omitempty"`
	Expires        string          `json:"expires"`
	Identifiers    []Identifier    `json:"identifiers,omitempty"`
	Finalize       string          `json:"finalize"`
	NotBefore      string          `json:"notBefore,omitempty"`
	NotAfter       string          `json:"notAfter,omitempty"`
	Authorizations []string        `json:"authorizations"`
	Certificate    string          `json:"certificate,omitempty"`
}

// An Authorization is created for each identifier in an order
type Authorization struct {
	Status     string      `json:"status"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
	Expires    string      `json:"expires"`
	// Wildcard is a Let's Encrypt specific Authorization field that indicates the
	// authorization was created as a result of an order containing a name with
	// a `*.`wildcard prefix. This will help convey to users that an
	// Authorization with the identifier `example.com` and one DNS-01 challenge
	// corresponds to a name `*.example.com` from an associated order.
	Wildcard bool `json:"wildcard,omitempty"`
}

// A Challenge is used to validate an Authorization
type Challenge struct {
	Type      string          `json:"type"`
	URL       string          `json:"url"`
	Token     string          `json:"token"`
	Status    string          `json:"status"`
	Validated string          `json:"validated,omitempty"`
	Error     *ProblemDetails `json:"error,omitempty"`
}


type SupportedCertAlgorithmsMessage struct {
	PQTLS PQTLSAlgo `json:"PQTLS"`
	KEMTLS KEMTLSAlgo `json:"KEMTLS"`
	KEMPOP KEMPOPAlgo `json:"KEM-POP"`
}

type PQTLSAlgo struct {
	Dilithium2  string `json:"Dilithium2"`
	Falcon512   string `json:"Falcon512"`
	SphincsShake128sSimple  string `json:"SphincsShake128sSimple"`
	Dilithium3	string `json:"Dilitihium3"`
	Dilithium5	string `json:"Dilithium5"`
	Falcon1024  string `json:"Falcon1024"`
	SphincsShake256sSimple  string `json:"SphincsShake256sSimple"`
	P256Dilithium2 string `json:"P256Dilithium2"`
	P256Falcon512 string `json:"P256Falcon512"`
	P256SphincsShake128sSimple  string `json:"P256SphincsShake128sSimple"`
	P384Dilithium3  string `json:"P384Dilithium3"`
	P521Dilithium5  string `json:"P521Dilithium5"`
	P521Falcon1024  string `json:"P521Falcon1024"`
	P521SphincsShake256sSimple  string `json:"P521SphincsShake256sSimple"`

}

type KEMTLSAlgo struct {

	KEMTLSWithFireSaber_KEM string `json:""`
	KEMTLSWithP256_Kyber512 string `json:""`
	KEMTLSWithP384_Kyber768 string `json:""`
	KEMTLSWithP521_Kyber1024 string `json:""`
	KEMTLSWithP256_LightSaber_KEM string `json:""`
	KEMTLSWithP384_Saber_KEM string `json:""`
	KEMTLSWithP521_FireSaber_KEM string `json:""`
	KEMTLSWithP256_NTRU_HPS_2048_509 string `json:""`
	KEMTLSWithP384_NTRU_HPS_2048_677 string `json:""`
	KEMTLSWithP521_NTRU_HPS_4096_821 string `json:""`
	KEMTLSWithP521_NTRU_HPS_4096_1229 string `json:""`
	KEMTLSWithP384_NTRU_HRSS_701 string `json:""`
	KEMTLSWithP521_NTRU_HRSS_1373 string `json:""`

}

type KEMPOPAlgo struct {
	Kyber string `json:"Kyber"`
	Frodo string `json:"Frodo"`
}




