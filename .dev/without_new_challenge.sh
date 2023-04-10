echo 'Testing ACME SERVER to issue classic and pq certificates (without new-challenge)'
echo ''

echo 'Loading config file'
source ../../tests/scripts/config.sh
echo ''

echo 'Running pebble'
cd ${PEBBLE_DIR}
echo ''

# -- supported pq and hybrid signature algorithm :  
# Dilithium2, Dilithium3, Dilithium5, Falcon-512, Falcon-1024, sphincs+-shake256-128s-simple, sphincs+-shake256-128s-simple
# P256_Dilithium2, P256_Falcon-512, P256_sphincs+-shake256-128s-simple, 
# P384_Dilithium3, P521_Dilithium5, P521_Falcon-1024, P521_sphincs+-SHAKE256-256s-simple

# -- supported classic signature algorithm:  
# ECDSA-P256, ECDSA-P384, ECDSA-P521


sigAlgo=ECDSA-P256
sigAlgoPQC=P256_Falcon-512


echo "new-challenge:" ${sigAlgoPQC}
go run cmd/pebble/main.go \
-pqtls \
-kex Kyber512 \
-newchallenge \
-rootSig ${sigAlgo} \
-interSig ${sigAlgo} \
-issuerSig ${sigAlgo} \
-rootdir ${PQCACME_TESTS_DIR}/root_ca \
--pqorderroot ${sigAlgoPQC} \
--pqorderissuer ${sigAlgoPQC} \
-timingcsv ${PQCACME_TESTS_DIR}/measurements/pebble_issuance_time.csv \
