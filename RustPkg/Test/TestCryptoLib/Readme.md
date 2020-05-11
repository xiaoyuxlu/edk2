## Rust crypto test

### How to Run:

./make-script.sh

cargo test

### crypto alogrithm in ring(a rust crypto library).

1. HASH - test_sha256
    SHA256, SHA384, SHA512, SHA512_256
2. HMAC - test_hmac
    HMAC_SHA256, HMAC_SHA384, HMAC_SHA512
3. RSA - test_rsa
    RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384,RSA_PKCS1_SHA512
4. ECDH - test_ecdh
    ECDH_P256, ECDH_P384
5. AEAD - test_aead
    AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305
6. ECDSA - test_ecdha
    ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA384_ASN1,
    ECDSA_P384_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA384_FIXED
