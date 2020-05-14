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
openssl pkcs8 -in private.der -inform DER -topk8 -nocrypt -outform DER > private.p8
openssl ec -pubout -inform der -in private.der -outform der -out public.der
popd


mkdir -p test/pki/rsa
pushd test/pki/rsa
openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ca.key -out ca.cert -sha256 -batch -subj "//CN=intel RSA CA"
openssl rsa -in ca.key -outform der -out ca.key.der
openssl asn1parse -in ca.cert -out ca.der

openssl req -nodes -newkey rsa:3072 -keyout inter.key -out inter.req -sha256 -batch -subj "//CN=intel RSA intermediate cert"
openssl req -nodes -newkey rsa:2048 -keyout end.key -out end.req -sha256 -batch -subj "//CN=test.com"

openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../../../openssl.cnf
openssl x509 -req -in end.req -out end.cert -CA inter.cert -CAkey inter.key -sha256 -days 365 -set_serial 2 -extensions v3_end -extfile ../../../openssl.cnf

openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end.cert -out end.cert.der
popd