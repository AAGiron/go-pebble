#!/bin/bash
cd /home/vvc/Desktop/LabSec/codes/wrapped_certificates/tests/src/scripts
source config.sh


cd ${PEBBLE_DIR}
go run cmd/pebble/main.go \
-pqtls \
-rootSig sphincsshake128ssimple \
-issuerSig dilithium2 \
-kex Kyber512 \
-rootdir ${WRAPPED_CERT_TESTS_DIR}/root_ca