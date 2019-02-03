// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2018 Isis Lovecruft and Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Jeff Burdges <jeff@web3.foundation>

//! Export, import, and use Ed25519 public keys. 
//!
//! Avoid using this module, except as a short-term transitional convenience.
//!
//! We warn that each Ristretto public key corresponds to two Ed25519 
//! public keys because ristretto involves a square root.  As such,
//! all methods provided here must be considered non-cannonical, 
//! meaning if another ristretto impleentation chooses another brnach
//! of the square root then the results will be incompatable.
//!
//! We do not expect vuonerabilities from this when merely using or
//! exporting Ristretto public keys as Ed25519 public keys, but
//! Ed25519 signatures created here may fail verification when used
//! with another Ristretto implementation.  
//!
//! We foresee worse when using `PublicKey::from_ed25519_public_key_bytes`
//! provided here because protocols might expose vulnerablities if they
//! import the same Ristretto key expecting two different keys.
//! As a minor example, two tightly related Ed25519 public keys used
//! with out our HDKD methods could yield the same derived keys.
//!
//! In the near future, we shall hide this module behind a "transitional"
//! feature flag due to these concerns.

use curve25519_dalek::digest;
use curve25519_dalek::digest::generic_array::typenum::U64;

use curve25519_dalek::edwards::{CompressedEdwardsY,EdwardsPoint};
use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use super::*;


type Ed25519Signature = [u8; ::ed25519_dalek::SIGNATURE_LENGTH];


/// Requires `RistrettoPoint` be defined as `RistrettoPoint(EdwardsPoint)`.
/// Any usage risks signature ed25519 verification failure when verifiers 
/// use another Ristretto implementation.
pub fn ristretto_to_edwards(p: RistrettoPoint) -> EdwardsPoint {
    unsafe { ::std::mem::transmute::<RistrettoPoint,EdwardsPoint>(p) }
}

/// Requires `RistrettoPoint` be defined as `RistrettoPoint(EdwardsPoint)`
///
/// Avoid using this function.  It is necessarily painfully slow.
pub fn edwards_to_ristretto(p: EdwardsPoint) -> Result<RistrettoPoint,SignatureError> {
    if ! p.is_torsion_free() {
        return Err(SignatureError::PointDecompressionError);
    }
    Ok(unsafe { ::std::mem::transmute::<EdwardsPoint,RistrettoPoint>(p) })
}


impl SecretKey {
    /// Sign a message with this `SecretKey` using the old Ed25519
    /// algorithm.
    ///
    /// Incurs a public key comression cost which Ed25519 normally avoids,
    /// making the `ed25519-dalek` crate faster.
    #[allow(non_snake_case)]
    pub fn sign_ed25519(&self, message: &[u8], public_key: &PublicKey) -> Ed25519Signature {
        let public_key = public_key.to_ed25519_public_key();
        self.to_ed25519_expanded_secret_key()
        .sign(message,&public_key).to_bytes()
    }

    /// Sign a `prehashed_message` with this `SecretKey` using the
    /// Ed25519ph algorithm defined in [RFC8032 §5.1][rfc8032].
    ///
    /// Incurs a public key comression cost which Ed25519ph normally avoids,
    /// making the `ed25519-dalek` crate faster.
    ///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    #[allow(non_snake_case)]
    pub fn sign_ed25519_prehashed<D>(
        &self,
        prehashed_message: D,
        public_key: &PublicKey,
        context: Option<&'static [u8]>,
    ) -> Ed25519Signature
    where D: digest::Digest<OutputSize = U64> + Default + Clone,
    {
        let public_key = public_key.to_ed25519_public_key();
        self.to_ed25519_expanded_secret_key()
        .sign_prehashed::<D>(prehashed_message,&public_key,context).to_bytes()
    }
}

impl PublicKey {
    /// A serialized Ed25519 public key compatable with our serialization
    /// of the corresponding `SecretKey`.  
    /// 
    /// We multiply by the cofactor 8 here because we multiply our
    /// scalars by the cofactor 8 in serialization as well.  In this way,
    /// our serializations remain somewhat ed25519 compatable, except for  
    /// clamping, but internally we only operate on honest scalars
    /// represented mod l, and thus avoid spooky cofactor bugs.
    pub fn to_ed25519_public_key_bytes(&self) -> [u8; 32] {
        ristretto_to_edwards(self.as_point().clone()).mul_by_cofactor().compress().to_bytes()
    }

    /// An Ed25519 public key compatable with our serialization of
    /// the corresponding `SecretKey`.  
    pub fn to_ed25519_public_key(&self) -> ::ed25519_dalek::PublicKey {
        let pkb = self.to_ed25519_public_key_bytes();
        ::ed25519_dalek::PublicKey::from_bytes(&pkb[..])
        .expect("Improper serialisation of Ed25519 public key!")
    }   

    /// Deserialized an Ed25519 public key compatable with our
    /// serialization of the corresponding `SecretKey`. 
    /// 
    /// Avoid using this function.  It is necessarily painfully slow,
    /// perahps the slowest in this crate, and will make you look bad. 
    /// It's also extremely dangerous because two different ed25519
    /// public keys import as the same Ristretto public key, which
    /// could concievably create vulnerabilities for more complex
    /// protocols built around Ristretto.
    /// Instead, communitate and use only Ristretto public keys, and
    /// convert to ed25519 keys as required.
    pub fn from_ed25519_public_key_bytes(bytes: &[u8]) -> Result<PublicKey, SignatureError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(SignatureError::BytesLengthError {
                name: "PublicKey",
        discription: "An ed25519 public key as a 32-byte compressed point, as specified in RFC8032",
                length: PUBLIC_KEY_LENGTH
            });
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        let mut point = edwards_to_ristretto(
            CompressedEdwardsY(bits).decompress()
            .ok_or(SignatureError::PointDecompressionError) ?
        ) ?;  // PointDecompressionError unless 2-torsion free
        let eighth = Scalar::from(8u8).invert();
        debug_assert_eq!(Scalar::one(), eighth * Scalar::from(8u8));
        point *= &eighth;
        Ok(PublicKey::from_point(point))
        // debug_assert_eq!(bytes,p.to_ed25519_public_key_bytes());
    }

    /// Verify a signature on a message with this public key.
    ///
    /// Incurs a public key comression cost which Ed25519 normally avoids,
    /// making the `ed25519-dalek` crate faster.
    #[allow(non_snake_case)]
    pub fn verify_ed25519(&self, message: &[u8], signature: &Ed25519Signature) -> bool {
        ::ed25519_dalek::Signature::from_bytes(&signature[..])
        .and_then(|s| self.to_ed25519_public_key().verify(message,&s)).is_ok()
    }

    /// Verify a `signature` on a `prehashed_message` using the
    /// Ed25519ph algorithm defined in [RFC8032 §5.1][rfc8032].
    ///
    /// Incurs a public key comression cost which Ed25519ph normally avoids,
    /// making the `ed25519-dalek` crate faster.
    ///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    #[allow(non_snake_case)]
    pub fn verify_ed25519_prehashed<D>(
        &self,
        prehashed_message: D,
        context: Option<&[u8]>,
        signature: &Ed25519Signature
    ) -> bool
    where D: digest::Digest<OutputSize = U64> + Default
    {
        ::ed25519_dalek::Signature::from_bytes(&signature[..])
        .and_then(|s| self.to_ed25519_public_key().verify_prehashed::<D>(prehashed_message,context,&s)).is_ok()
    }
}

impl Keypair {
    /// Sign a message with this `SecretKey` using ed25519.
    #[allow(non_snake_case)]
    pub fn sign_ed25519(&self, message: &[u8]) -> Ed25519Signature {
        self.secret.sign_ed25519(message, &self.public)
    }

    /// Sign a `prehashed_message` with this `SecretKey` using the
    /// Ed25519ph algorithm defined in [RFC8032 §5.1][rfc8032].
    #[allow(non_snake_case)]
    pub fn sign_ed25519_prehashed<D>(
        &self,
        prehashed_message: D,
        context: Option<&'static [u8]>,
    ) -> Ed25519Signature
    where D: digest::Digest<OutputSize = U64> + Default + Clone,
    {
        self.secret.sign_ed25519_prehashed::<D>(prehashed_message, &self.public, context)
    }

    /// Verify a signature on a message with this public key.
    ///
    /// Incurs a public key comression cost which Ed25519 normally avoids,
    /// making the `ed25519-dalek` crate faster.
    #[allow(non_snake_case)]
    pub fn verify_ed25519(&self, message: &[u8], signature: &Ed25519Signature) -> bool {
        self.public.verify_ed25519(message,signature)
    }

    /// Verify a `signature` on a `prehashed_message` using the
    /// Ed25519ph algorithm defined in [RFC8032 §5.1][rfc8032].
    ///
    /// Incurs a public key comression cost which Ed25519ph normally avoids,
    /// making the `ed25519-dalek` crate faster.
    ///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    #[allow(non_snake_case)]
    #[allow(non_snake_case)]
    pub fn verify_ed25519_prehashed<D>(
        &self,
        prehashed_message: D,
        context: Option<&[u8]>,
        signature: &Ed25519Signature
    ) -> bool
    where D: digest::Digest<OutputSize = U64> + Default
    {
        self.public.verify_ed25519_prehashed::<D>(prehashed_message,context,signature)
    }
}


#[cfg(test)]
mod test {
    use std::vec::Vec;
    use hex::FromHex;
    // use rand::prelude::*; // ThreadRng,thread_rng
    use sha2::{Sha512,Digest};
    use super::*;

    /* *** We have no test vectors obviously ***

    use std::io::BufReader;
    use std::io::BufRead;
    use std::fs::File;
    use std::string::String;

    // TESTVECTORS is taken from sign.input.gz in agl's ed25519 Golang
    // package. It is a selection of test cases from
    // http://ed25519.cr.yp.to/python/sign.input
    #[cfg(test)]
    #[cfg(not(release))]
    #[test]
    fn golden() { // TestGolden
        let mut line: String;
        let mut lineno: usize = 0;

        let f = File::open("TESTVECTORS");
        if f.is_err() {
            println!("This test is only available when the code has been cloned \
                      from the git repository, since the TESTVECTORS file is large \
                      and is therefore not included within the distributed crate.");
            panic!();
        }
        let file = BufReader::new(f.unwrap());

        for l in file.lines() {
            lineno += 1;
            line = l.unwrap();

            let parts: Vec<&str> = line.split(':').collect();
            assert_eq!(parts.len(), 5, "wrong number of fields in line {}", lineno);

            let sec_bytes: Vec<u8> = FromHex::from_hex(&parts[0]).unwrap();
            let pub_bytes: Vec<u8> = FromHex::from_hex(&parts[1]).unwrap();
            let msg_bytes: Vec<u8> = FromHex::from_hex(&parts[2]).unwrap();
            let sig_bytes: Vec<u8> = FromHex::from_hex(&parts[3]).unwrap();

            let secret: MiniSecretKey = MiniSecretKey::from_bytes(&sec_bytes[..MINI_SECRET_KEY_LENGTH]).unwrap();
            let public: PublicKey = PublicKey::from_bytes(&pub_bytes[..PUBLIC_KEY_LENGTH]).unwrap();
            let keypair: Keypair  = Keypair{ secret: secret, public: public };

            // The signatures in the test vectors also include the message
            // at the end, but we just want R and S.
            let sig1: Signature = Signature::from_bytes(&sig_bytes[..64]).unwrap();
            let sig2: Signature = keypair.sign::<Sha512>(&msg_bytes);

            assert!(sig1 == sig2, "Signature bytes not equal on line {}", lineno);
            assert!(keypair.verify::<Sha512>(&msg_bytes, &sig2),
                    "Signature verification failed on line {}", lineno);
        }
    }
    *** We have no test vectors obviously *** */

    // From https://tools.ietf.org/html/rfc8032#section-7.3
    #[test]
    fn ed25519ph_rf8032_test_vector() {
        let secret_key: &[u8] = b"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
        let public_key: &[u8] = b"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
        let message: &[u8] = b"616263";
        let sig1: &[u8] = b"98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406";

        let sec_bytes: Vec<u8> = FromHex::from_hex(secret_key).unwrap();
        let pub_bytes: Vec<u8> = FromHex::from_hex(public_key).unwrap();
        let msg_bytes: Vec<u8> = FromHex::from_hex(message).unwrap();
        let sig1: Vec<u8> = FromHex::from_hex(sig1).unwrap();

        let secret: MiniSecretKey = MiniSecretKey::from_bytes(&sec_bytes[..MINI_SECRET_KEY_LENGTH]).unwrap();
        let public: PublicKey = PublicKey::from_ed25519_public_key_bytes(&pub_bytes[..PUBLIC_KEY_LENGTH]).unwrap();
        let keypair: Keypair  = Keypair{ secret: secret.expand::<Sha512>(), public: public };

        let prehash_for_signing: Sha512 = Sha512::default().chain(&msg_bytes[..]);
        let prehash_for_verifying: Sha512 = Sha512::default().chain(&msg_bytes[..]);

        let sig2 = keypair.sign_ed25519_prehashed(prehash_for_signing, None);

        assert!(&sig1[..] == &sig2[..],
                "Original signature from test vectors doesn't equal signature produced:\
                \noriginal:\n{:?}\nproduced:\n{:?}", &sig1[..], &sig2[..]);
        assert!(keypair.verify_ed25519_prehashed(prehash_for_verifying, None, &sig2),
                "Could not verify ed25519ph signature!");
    }
}
