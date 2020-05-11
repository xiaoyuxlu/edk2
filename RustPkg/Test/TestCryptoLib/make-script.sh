#!/bin/sh

rm -rf test
mkdir -p test/rsa
pushd test/rsa
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -outform DER > private.der
openssl rsa -inform DER -in private.der -outform DER -RSAPublicKey_out > public.der
popd

mkdir -p test/ecdsa
pushd test/ecdsa
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -outform DER > private.der
openssl.exe pkcs8 -in private.der -inform DER -topk8 -nocrypt -outform DER > private.p8
openssl.exe ec -pubout -inform der -in private.der -outform der -out public.der
popd
