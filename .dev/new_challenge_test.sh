
# source ${WRAPPED_CERT_TESTS_DIR}/scripts/config.sh
source /home/vvc/Desktop/LabSec/codes/wrapped_certificates/go-hybrid-tests/scripts/config.sh

echo "NEWChallenge: Dilithium2"
go run cmd/pebble/main.go cmd/pebble/newchallenge.go \
-pqtls \
-kex Kyber512 \
-rootSig ECDSA-P256 \
-interSig ECDSA-P256 \
-issuerSig ECDSA-P256 \
-rootdir ${WRAPPED_CERT_TESTS_DIR}/root_ca \
-timingcsv ${WRAPPED_CERT_TESTS_DIR}/measurements/pebble_issuance_time.csv \