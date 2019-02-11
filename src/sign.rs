// -*- mode: rust; -*-
//
// This file is part of schnorrkel.
// Copyright (c) 2019 Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - jeffrey Burdges <jeff@web3.foundation>

//! Schnorr signature creation and verification,
//! including batch verification.


use core::fmt::{Debug};

use rand::prelude::*;  // {RngCore,thread_rng};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};
#[cfg(feature = "serde")]
use serde::{Serializer, Deserializer};
#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto,RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use super::*;
use crate::context::{SigningTranscript,SigningContext};


// === Actual signature type === //

/// The length of a curve25519 EdDSA `Signature`, in bytes.
pub const SIGNATURE_LENGTH: usize = 64;

/// A Ristretto Schnorr signature "detached" from the signed message.
///
/// These cannot be converted to any Ed25519 signature because they hash
/// curve points in the Ristretto encoding.
#[allow(non_snake_case)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Signature {
    /// `R` is an `EdwardsPoint`, formed by using an hash function with
    /// 512-bits output to produce the digest of:
    ///
    /// - the nonce half of the `SecretKey`, and
    /// - the message to be signed.
    ///
    /// This digest is then interpreted as a `Scalar` and reduced into an
    /// element in ℤ/lℤ.  The scalar is then multiplied by the distinguished
    /// basepoint to produce `R`, and `EdwardsPoint`.
    pub (crate) R: CompressedRistretto,

    /// `s` is a `Scalar`, formed by using an hash function with 512-bits output
    /// to produce the digest of:
    ///
    /// - the `r` portion of this `Signature`,
    /// - the `PublicKey` which should be used to verify this `Signature`, and
    /// - the message to be signed.
    ///
    /// This digest is then interpreted as a `Scalar` and reduced into an
    /// element in ℤ/lℤ.
    pub (crate) s: Scalar,
}

impl Debug for Signature {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "Signature( R: {:?}, s: {:?} )", &self.R, &self.s)
    }
}

impl Signature {
    const DISCRIPTION : &'static str = "A 64 byte Ristretto Schnorr signature";
    /*
    const DISCRIPTION_LONG : &'static str = 
        "A 64 byte Ristretto Schnorr signature, similar to an ed25519 \
         signature as specified in RFC8032, except the Ristretto point \
         compression is used for the curve point in the first 32 bytes";
    */
    
    /// Convert this `Signature` to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut signature_bytes: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];

        signature_bytes[..32].copy_from_slice(&self.R.as_bytes()[..]);
        signature_bytes[32..].copy_from_slice(&self.s.as_bytes()[..]);
        signature_bytes
    }

    /// Construct a `Signature` from a slice of bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, SignatureError> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(SignatureError::BytesLengthError {
                name: "Signature",
                discription: Signature::DISCRIPTION,
                length: SIGNATURE_LENGTH
            });
        }
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[..32]);
        upper.copy_from_slice(&bytes[32..]);

        let s = Scalar::from_canonical_bytes(upper).ok_or(SignatureError::ScalarFormatError) ?;
        Ok(Signature{ R: CompressedRistretto(lower), s })
    }
}

serde_boilerplate!(Signature);


// === Implement signing and verification operations on key types === //

impl SecretKey {
    /// Sign a transcript with this `SecretKey`.
    ///
    /// Requires a `SigningTranscript`, normally created from a
    /// `SigningContext` and a message, as well as the public key
    /// correspodning to `self`.  Returns a Schnorr signature.
    ///
    /// We employ a randomized nonce here, but also incorporate the
    /// transcript like in a derandomized scheme, but only after first
    /// extending the transcript by the public key.  As a result, there
    /// should be no attacks even if both the random number generator
    /// fails and the function gets called with the wrong public key.
    #[allow(non_snake_case)]
    pub fn sign<T: SigningTranscript>(&self, mut t: T, public_key: &PublicKey) -> Signature 
    {
        let R: CompressedRistretto;
        let r: Scalar;
        let s: Scalar;
        let k: Scalar;

        t.proto_name(b"Schnorr-sig");
        t.commit_point(b"A",public_key.as_compressed());

        r = t.witness_scalar(&self.nonce,None);  // context, message, A/public_key
        R = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();

        t.commit_point(b"R",&R);

        k = t.challenge_scalar(b"");  // context, message, A/public_key, R=rG
        s = &(&k * &self.key) + &r;

        Signature{ R, s }
    }

    /// Sign a message with this `SecretKey`.
    pub fn sign_simple(&self, ctx: &'static [u8], msg: &[u8], public_key: &PublicKey) -> Signature
    {
        let t = SigningContext::new(ctx).bytes(msg);
        self.sign(t,public_key)
    }
}


impl PublicKey {
    /// Verify a signature by this public key on a transcript.
    ///
    /// Requires a `SigningTranscript`, normally created from a
    /// `SigningContext` and a message, as well as the signature
    /// to be verified.
    #[allow(non_snake_case)]
    pub fn verify<T: SigningTranscript>(&self, mut t: T, signature: &Signature) -> bool
    {
        let A: &RistrettoPoint = self.as_point();
        let R: RistrettoPoint;
        let k: Scalar;

        t.proto_name(b"Schnorr-sig");
        t.commit_point(b"A",self.as_compressed());
        t.commit_point(b"R",&signature.R);

        k = t.challenge_scalar(b"");  // context, message, A/public_key, R=rG
        R = RistrettoPoint::vartime_double_scalar_mul_basepoint(&k, &(-A), &signature.s);

        R.compress() == signature.R
    }

    /// Verify a signature by this public key on a message.
    pub fn verify_simple(&self, ctx: &'static [u8], msg: &[u8], signature: &Signature) -> bool
    {
        let t = SigningContext::new(ctx).bytes(msg);
        self.verify(t,signature)
    }
}


/// Verify a batch of `signatures` on `messages` with their respective `public_keys`.
///
/// # Inputs
///
/// * `messages` is a slice of byte slices, one per signed message.
/// * `signatures` is a slice of `Signature`s.
/// * `public_keys` is a slice of `PublicKey`s.
/// * `csprng` is an implementation of `Rng + CryptoRng`, such as `rand::ThreadRng`.
///
/// # Panics
///
/// This function will panic if the `messages, `signatures`, and `public_keys`
/// slices are not equal length.
///
/// # Returns
///
/// * A `Result` whose `Ok` value is an emtpy tuple and whose `Err` value is a
///   `SignatureError` containing a description of the internal error which
///   occured.
///
/// # Examples
///
/// ```
/// extern crate schnorrkel;
/// extern crate rand;
///
/// use schnorrkel::{Keypair,PublicKey,Signature,verify_batch,signing_context};
/// use rand::thread_rng;
/// use rand::rngs::ThreadRng;
///
/// # fn main() {
/// let ctx = signing_context(b"some batch");
/// let mut csprng: ThreadRng = thread_rng();
/// let keypairs: Vec<Keypair> = (0..64).map(|_| Keypair::generate(&mut csprng)).collect();
/// let msg: &[u8] = b"They're good dogs Brant";
/// let signatures:  Vec<Signature> = keypairs.iter().map(|key| key.sign(ctx.bytes(&msg))).collect();
/// let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
///
/// let transcripts = ::std::iter::once(ctx.bytes(msg)).cycle().take(64);
///
/// assert!( verify_batch(transcripts, &signatures[..], &public_keys[..]) );
/// # }
/// ```
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(non_snake_case)]
pub fn verify_batch<T,I>(
    transcripts: I,
    signatures: &[Signature],
    public_keys: &[PublicKey]
) -> bool
where
    T: SigningTranscript, 
    I: IntoIterator<Item=T>,
{
    const ASSERT_MESSAGE: &'static [u8] = b"The number of messages/transcripts, signatures, and public keys must be equal.";
    assert!(signatures.len() == public_keys.len(), ASSERT_MESSAGE);  // Check transcripts length below

    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use std::vec::Vec;

    use core::iter::once;

    use curve25519_dalek::traits::IsIdentity;
    use curve25519_dalek::traits::VartimeMultiscalarMul;

    let mut rng = rand::prelude::thread_rng();
    
    // Select a random 128-bit scalar for each signature.
    let zs: Vec<Scalar> = signatures.iter()
        .map(|_| Scalar::from(rng.gen::<u128>()))
        .collect();

    // Compute the basepoint coefficient, ∑ s[i]z[i] (mod l)
    let B_coefficient: Scalar = signatures.iter()
        .map(|sig| sig.s)
        .zip(zs.iter())
        .map(|(s, z)| z * s)
        .sum();

    /*
    let hrams = (0..signatures.len()).map(|i| {
        let mut t = transcripts[i].borrow().clone();
        t.proto_name(b"Schnorr-sig");
        t.commit_point(b"A",public_keys[i].as_compressed());
        t.commit_point(b"R",&signatures[i].R);
        t.challenge_scalar(b"")  // context, message, A/public_key, R=rG
    });
    */
    // We might collect here anyways, but right now you cannot have
    //   IntoIterator<Item=T, IntoIter: ExactSizeIterator+TrustedLen>
    // Begin NLL hack
    let mut transcripts = transcripts.into_iter();
    let zhrams: Vec<Scalar> = {// NLL hack
    // Compute H(R || A || M) for each (signature, public_key, message) triplet
    let hrams = transcripts.by_ref()
        .zip(0..signatures.len())
        .map( |(mut t,i)| {
            t.proto_name(b"Schnorr-sig");
            t.commit_point(b"A",public_keys[i].as_compressed());
            t.commit_point(b"R",&signatures[i].R);
            t.challenge_scalar(b"")  // context, message, A/public_key, R=rG
        } );

    // Multiply each H(R || A || M) by the random value
    hrams.zip(zs.iter()).map(|(hram, z)| hram * z).collect()
    }; 
    // End NLL hack
    assert!(transcripts.next().is_none(), ASSERT_MESSAGE);
    assert!(zhrams.len() == public_keys.len(), ASSERT_MESSAGE);

    let Rs = signatures.iter().map(|sig| sig.R.decompress());
    let As = public_keys.iter().map(|pk| Some(pk.as_point().clone()));
    let B = once(Some(constants::RISTRETTO_BASEPOINT_POINT));

    // Compute (-∑ z[i]s[i] (mod l)) B + ∑ z[i]R[i] + ∑ (z[i]H(R||A||M)[i] (mod l)) A[i] = 0
    RistrettoPoint::optional_multiscalar_mul(
        once(-B_coefficient).chain(zs.iter().cloned()).chain(zhrams),
        B.chain(Rs).chain(As),
    ).map(|id| id.is_identity()).unwrap_or(false)
    // We need not return SigenatureError::PointDecompressionError because
    // the decompression failures occur for R represent invalid signatures.
}


impl Keypair {
    /// Sign a transcript with this keypair's secret key.
    ///
    /// Requires a `SigningTranscript`, normally created from a
    /// `SigningContext` and a message.  Returns a Schnorr signature.
    ///
    /// # Examples
    ///
    /// Internally, we manage signature transcripts using a 128 bit secure
    /// STROBE construction based on Keccak, which itself is extremly fast
    /// and secure.  You might however influence performance or security
    /// by prehashing your message, like
    ///
    /// ```
    /// extern crate schnorrkel;
    /// extern crate rand;
    /// extern crate sha3;
    ///
    /// use schnorrkel::{Signature,Keypair};
    /// use rand::prelude::*; // ThreadRng,thread_rng
    /// use sha3::Shake128;
    /// use sha3::digest::{Input};
    ///
    /// # #[cfg(all(feature = "std"))]
    /// # fn main() {
    /// let mut csprng: ThreadRng = thread_rng();
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
    /// let message: &[u8] = b"All I want is to pet all of the dogs.";
    ///
    /// // Create a hash digest object and feed it the message:
    /// let prehashed = Shake128::default().chain(message);
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "std")))]
    /// # fn main() { }
    /// ```
    ///
    /// We require a "context" string for all signatures, which should
    /// be chosen judiciously for your project.  It should represent the 
    /// role the signature plays in your application.  If you use the
    /// context in two purposes, and the same key, then a signature for
    /// one purpose can be substituted for the other.
    ///
    /// ```
    /// # extern crate schnorrkel;
    /// # extern crate rand;
    /// # extern crate sha3;
    /// #
    /// # use schnorrkel::{Keypair,Signature,signing_context};
    /// # use rand::prelude::*; // ThreadRng,thread_rng
    /// # use sha3::digest::Input;
    /// #
    /// # #[cfg(all(feature = "std"))]
    /// # fn main() {
    /// # let mut csprng: ThreadRng = thread_rng();
    /// # let keypair: Keypair = Keypair::generate(&mut csprng);
    /// # let message: &[u8] = b"All I want is to pet all of the dogs.";
    /// # let prehashed = ::sha3::Shake256::default().chain(message);
    /// #
    /// let ctx = signing_context(b"My Signing Context");
    ///
    /// let sig: Signature = keypair.sign(ctx.xof(prehashed));
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "std")))]
    /// # fn main() { }
    /// ```
    ///
    // lol  [terrible_idea]: https://github.com/isislovecruft/scripts/blob/master/gpgkey2bc.py
    pub fn sign<T: SigningTranscript>(&self, t: T) -> Signature
    {
        self.secret.sign(t, &self.public)
    }

    /// Sign a message with this keypair's secret key.
    pub fn sign_simple(&self, ctx: &'static [u8], msg: &[u8]) -> Signature
    {
        self.secret.sign_simple(ctx, msg, &self.public)
    }

    /// Verify a signature by keypair's public key on a transcript.
    ///
    /// Requires a `SigningTranscript`, normally created from a
    /// `SigningContext` and a message, as well as the signature
    /// to be verified.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate schnorrkel;
    /// extern crate rand;
    ///
    /// use schnorrkel::{Keypair,Signature,signing_context};
    /// use rand::prelude::*; // ThreadRng,thread_rng
    ///
    /// # fn main() {
    /// let mut csprng: ThreadRng = thread_rng();
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
    /// let message: &[u8] = b"All I want is to pet all of the dogs.";
    ///
    /// let ctx = signing_context(b"Some context string");
    ///
    /// let sig: Signature = keypair.sign(ctx.bytes(message));
    ///
    /// assert!( keypair.public.verify(ctx.bytes(message), &sig) );
    /// # }
    /// ```
    pub fn verify<T: SigningTranscript>(&self, t: T, signature: &Signature) -> bool
    {
        self.public.verify(t, signature)
    }

    /// Verify a signature by keypair's public key on a message.
    pub fn verify_simple(&self, ctx: &'static [u8], msg: &[u8], signature: &Signature) -> bool
    {
        self.public.verify_simple(ctx, msg, signature)
    }
}


#[cfg(test)]
mod test {
    use std::vec::Vec;
    use rand::prelude::*; // ThreadRng,thread_rng
    use rand_chacha::ChaChaRng;
    use sha3::Shake128;
    use curve25519_dalek::digest::{Input};

    use super::super::*;


    #[test]
    fn sign_verify_bytes() {
        let mut csprng: ChaChaRng;
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig:  Signature;

        let ctx = signing_context(b"good");
        
        let good: &[u8] = "test message".as_bytes();
        let bad:  &[u8] = "wrong message".as_bytes();

        csprng  = ChaChaRng::from_seed([0u8; 32]);
        keypair  = Keypair::generate(&mut csprng);
        good_sig = keypair.sign(ctx.bytes(&good));
        bad_sig  = keypair.sign(ctx.bytes(&bad));

        assert!(keypair.verify(ctx.bytes(&good), &good_sig),
                "Verification of a valid signature failed!");
        assert!(!keypair.verify(ctx.bytes(&good), &bad_sig),
                "Verification of a signature on a different message passed!");
        assert!(!keypair.verify(ctx.bytes(&bad),  &good_sig),
                "Verification of a signature on a different message passed!");
        assert!(!keypair.verify(signing_context(b"bad").bytes(&good),  &good_sig),
                "Verification of a signature on a different message passed!");
    }

    #[test]
    fn sign_verify_xof() {
        let mut csprng: ChaChaRng;
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig:  Signature;

        let ctx = signing_context(b"testing testing 1 2 3");

        let good: &[u8] = b"test message";
        let bad:  &[u8] = b"wrong message";

        let prehashed_good: Shake128 = Shake128::default().chain(good);
        let prehashed_bad: Shake128 = Shake128::default().chain(bad);
        // You may verify that `Shake128: Copy` is possible, making these clones below correct.

        csprng   = ChaChaRng::from_seed([0u8; 32]);
        keypair  = Keypair::generate(&mut csprng);
        good_sig = keypair.sign(ctx.xof(prehashed_good.clone()));
        bad_sig  = keypair.sign(ctx.xof(prehashed_bad.clone()));

        assert!(keypair.verify(ctx.xof(prehashed_good.clone()), &good_sig),
                "Verification of a valid signature failed!");
        assert!(! keypair.verify(ctx.xof(prehashed_good.clone()), &bad_sig),
                "Verification of a signature on a different message passed!");
        assert!(! keypair.verify(ctx.xof(prehashed_bad.clone()), &good_sig),
                "Verification of a signature on a different message passed!");
        assert!(! keypair.verify(signing_context(b"oops").xof(prehashed_good), &good_sig),
                "Verification of a signature on a different message passed!");
    }

    #[test]
    fn verify_batch_seven_signatures() {
        let ctx = signing_context(b"my batch context");

        let messages: [&[u8]; 7] = [
            b"Watch closely everyone, I'm going to show you how to kill a god.",
            b"I'm not a cryptographer I just encrypt a lot.",
            b"Still not a cryptographer.",
            b"This is a test of the tsunami alert system. This is only a test.",
            b"Fuck dumbin' it down, spit ice, skip jewellery: Molotov cocktails on me like accessories.",
            b"Hey, I never cared about your bucks, so if I run up with a mask on, probably got a gas can too.",
            b"And I'm not here to fill 'er up. Nope, we came to riot, here to incite, we don't want any of your stuff.", ];
        let mut csprng: ThreadRng = thread_rng();
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut signatures: Vec<Signature> = Vec::new();

        for i in 0..messages.len() {
            let keypair: Keypair = Keypair::generate(&mut csprng);
            signatures.push(keypair.sign(ctx.bytes(messages[i])));
            keypairs.push(keypair);
        }
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
        let transcripts = messages.iter().map(|m| ctx.bytes(m));

        assert!( verify_batch(transcripts, &signatures[..], &public_keys[..]) );
    }
}

