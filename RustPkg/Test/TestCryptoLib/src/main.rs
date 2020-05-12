fn main() {

}

#[cfg(test)]
mod test {

    #[test]
    fn test_sha256() {
        use ring::{digest, test};
        let expected_hex = "96eebba49dbbf422d245f02290f9d4ed0eb02da9daa6bbceefb162800ff42481";
        let expected: Vec<u8> = test::from_hex(expected_hex).unwrap();
        let actual = digest::digest(&digest::SHA256, b"intel");
        assert_eq!(&expected, &actual.as_ref());
    }

    #[test]
    fn test_aead() {
        use ring::aead::{NonceSequence, Nonce as OldNonce, NONCE_LEN};
        use ring::rand::generate;
        use ring::rand::{SystemRandom};
        use ring::aead::{self, OpeningKey, SealingKey, BoundKey, UnboundKey};
        use ring::pbkdf2::{self};

        #[derive(Copy,Clone)]
        struct Nonce([u8;12]);

        impl NonceSequence for Nonce {
            fn advance(&mut self) -> Result<OldNonce, ring::error::Unspecified>{
                Ok(OldNonce::assume_unique_for_key(self.0))
            }
        }
        impl Nonce {
            pub fn new() -> Self{
                let mut nonce = [0u8;NONCE_LEN];
                let rng = SystemRandom::new();
                let r : [u8; 16] = generate(&rng).unwrap().expose();
                for i in 0..NONCE_LEN {
                    nonce[i] = r[i];
                }
                Self(nonce)
            }
        }

        let password = b"intel";

        let salt = [0,1,2,3,4,5,6,7];
        let nonce = Nonce::new();

        let mut key = [0u8;32];
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, std::num::NonZeroU32::new(100).unwrap(),  &salt, &password[..], &mut key);

        let content = b"hello world";

        let mut in_out = content.clone().to_vec();

        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &key).unwrap();
        let mut sealing_key = SealingKey::new(unbound_key, nonce.clone());

        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &key).unwrap();
        let mut opening_key = OpeningKey::new(unbound_key, nonce.clone());

        let _tag = sealing_key.seal_in_place_append_tag(ring::aead::Aad::empty(), &mut in_out).unwrap();
        println!("Encrypted data's size {}", in_out.len());

        let res = opening_key.open_in_place(ring::aead::Aad::empty(), &mut in_out).unwrap();

        println!("Decrypted data: {:?}", String::from_utf8(res.to_vec()).unwrap());
        assert_eq!(content, res);
    }

    #[test]
    fn test_hmac() {
        use ring::{digest, hmac, rand};

        let msg = "hello, world";

        let rng = rand::SystemRandom::new();
        let key_value: [u8; digest::SHA256_OUTPUT_LEN] = rand::generate(&rng).unwrap().expose();

        let s_key = hmac::Key::new(hmac::HMAC_SHA256, key_value.as_ref());
        let tag = hmac::sign(&s_key, msg.as_bytes());

        let v_key = hmac::Key::new(hmac::HMAC_SHA256, key_value.as_ref());
        hmac::verify(&v_key, msg.as_bytes(), tag.as_ref()).unwrap();
    }

    use ring::rand;
    use ring::signature::{self, RsaEncoding, VerificationAlgorithm};
    use untrusted;
    fn test_rsa_check(padding_alg: &'static dyn RsaEncoding, algorithm: &'static dyn VerificationAlgorithm) {
        // openssl.exe genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -outform DER > private.der
        let key_bytes_der =
           untrusted::Input::from(include_bytes!("..\\test\\rsa\\private.der")).as_slice_less_safe();
        let key_pair: signature::RsaKeyPair = signature::RsaKeyPair::from_der(key_bytes_der).unwrap();

        const MESSAGE: &'static [u8] = b"hello, world";
        let rng = rand::SystemRandom::new();

        let mut sign = vec![0; key_pair.public_modulus_len()];
        key_pair.sign(padding_alg, &rng, &MESSAGE, &mut sign).unwrap();

        // Verify the signature.
        // openssl.exe rsa -inform DER -in private.der -outform DER -RSAPublicKey_out > public.der
        let public_key_bytes_der = untrusted::Input::from(include_bytes!("..\\test\\rsa\\public.der")).as_slice_less_safe();
        let pubkey = signature::UnparsedPublicKey::new(algorithm, public_key_bytes_der);
        pubkey.verify(&MESSAGE, &sign).unwrap();
    }
    #[test]
    fn test_rsa() {
        // RSA PSS padding using SHA-256 for RSA signatures
        test_rsa_check(&signature::RSA_PSS_SHA256, &signature::RSA_PSS_2048_8192_SHA256);

        // PKCS#1 1.5 padding using SHA-256 for RSA signatures.
        test_rsa_check(&signature::RSA_PKCS1_SHA256, &signature::RSA_PKCS1_2048_8192_SHA256);
    }


    #[test]
    fn test_ecdh() {
     use ring::agreement;

     let rng = rand::SystemRandom::new();

     let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();

     // Make `my_public_key` a byte slice containing my public key. In a real
     // application, this would be sent to the peer in an encoded protocol
     // message.
     let _my_public_key = my_private_key.compute_public_key().unwrap();

     let peer_public_key = {
         // In a real application, the peer public key would be parsed out of a
         // protocol message. Here we just generate one.
         let peer_public_key = {
             let peer_private_key =
                 agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
             peer_private_key.compute_public_key().unwrap()
         };

         agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_key)
     };

     agreement::agree_ephemeral(
         my_private_key,
         &peer_public_key,
         ring::error::Unspecified,
         |key_material| {
             println!("key_material len() {}", key_material.len());
             assert_eq!(32, key_material.len());
             Ok(())
         },
     ).unwrap();
    }

    #[test]
    fn test_ecdsa() {
        // openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -outform DER > private.der
        // or  openssl.exe ecparam -name prime256v1 -genkey -out private.der -outform der
        // openssl.exe pkcs8 -in private.der -inform DER -topk8 -nocrypt -outform DER > private.p8
        use ring::signature::KeyPair;
        let key_bytes_der = untrusted::Input::from(include_bytes!("..\\test\\ecdsa\\private.p8")).as_slice_less_safe();
        let key_pair: signature::EcdsaKeyPair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING, &key_bytes_der).unwrap();

        const MESSAGE: &'static [u8] = b"hello, world";
        let rng = rand::SystemRandom::new();
        let sign = key_pair.sign(&rng, &MESSAGE).unwrap();
        let public_key = key_pair.public_key().as_ref();

        // Verify the signature.
        // questions:  openssl.exe ec -pubout -inform der -in private.der -outform der -out public.der
        // the pubkey openssl generate from private key can't use directory for ring.
        let public_key_bytes_der = untrusted::Input::from(include_bytes!("..\\test\\ecdsa\\public.der")).as_slice_less_safe();
        // openssl output public.der may have header.
        let pubkey = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &public_key_bytes_der[26..]);
        println!("public key1: {:?}", public_key);
        println!("public key2: {:?}", public_key_bytes_der);
        assert_ne!(public_key, public_key_bytes_der);
        pubkey.verify(&MESSAGE, sign.as_ref()).unwrap();
    }

    #[test]
    fn test_pki_verify_sign(){
        use webpki::{self, EndEntityCert};
        let cert_der = untrusted::Input::from(include_bytes!("..\\test\\pki\\rsa\\ca.der")).as_slice_less_safe();
        let cert = EndEntityCert::from(cert_der).unwrap();

        let key_bytes_der =
        untrusted::Input::from(include_bytes!("..\\test\\pki\\rsa\\ca.key.der")).as_slice_less_safe();
        let key_pair: signature::RsaKeyPair = signature::RsaKeyPair::from_der(key_bytes_der).unwrap();

        const MESSAGE: &'static [u8] = b"hello, world";
        let rng = rand::SystemRandom::new();

        let mut sign = vec![0; key_pair.public_modulus_len()];
        key_pair.sign(&signature::RSA_PKCS1_SHA256, &rng, &MESSAGE, &mut sign).unwrap();
        // key_pair.sign(&signature::RSA_PSS_SHA256, &rng, &MESSAGE, &mut sign).unwrap();

        //RSA_PSS_SHA256
        cert.verify_signature(&webpki::RSA_PKCS1_2048_8192_SHA256, &MESSAGE, &sign).unwrap();
        // cert.verify_signature(&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY, &MESSAGE, &sign).unwrap();
    }
}
