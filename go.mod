module github.com/letsencrypt/pebble/v2

require (
	github.com/letsencrypt/challtestsrv v1.2.1
	github.com/miekg/dns v1.1.48
	gopkg.in/square/go-jose.v2 v2.6.0
)

require (
	golang.org/x/net v0.0.0-20220412020605-290c469a71a5 // indirect
	golang.org/x/sys v0.0.0-20220412211240-33da011f77ad // indirect
	golang.org/x/tools v0.1.10 // indirect
	golang.org/x/xerrors v0.0.0-20220411194840-2f41105eb62f // indirect
)

go 1.16

replace gopkg.in/square/go-jose.v2 => ../go-jose
