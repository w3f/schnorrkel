// -*- mode: rust; -*-
//
// This file is part of schnorrkel.
// Copyright (c) 2019 Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - jeffrey Burdges <jeff@web3.foundation>

//! ### Schnorr signature batch verification.

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{RistrettoPoint}; // CompressedRistretto
use curve25519_dalek::scalar::Scalar;

use super::*;
use crate::context::{SigningTranscript};


/// Verify a batch of `signatures` on `messages` with their respective `public_keys`.
///
/// # Inputs
///
/// * `messages` is a slice of byte slices, one per signed message.
/// * `signatures` is a slice of `Signature`s.
/// * `public_keys` is a slice of `PublicKey`s.
/// * `deduplicate_public_keys` 
/// * `csprng` is an implementation of `RngCore+CryptoRng`, such as `rand::ThreadRng`.
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
/// use schnorrkel::{Keypair,PublicKey,Signature,verify_batch,signing_context};
///
/// # fn main() {
/// let ctx = signing_context(b"some batch");
/// let mut csprng = rand::thread_rng();
/// let keypairs: Vec<Keypair> = (0..64).map(|_| Keypair::generate_with(&mut csprng)).collect();
/// let msg: &[u8] = b"They're good dogs Brant";
/// let signatures:  Vec<Signature> = keypairs.iter().map(|key| key.sign(ctx.bytes(&msg))).collect();
/// let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
///
/// let transcripts = ::std::iter::once(ctx.bytes(msg)).cycle().take(64);
///
/// assert!( verify_batch(transcripts, &signatures[..], &public_keys[..], false).is_ok() );
/// # }
/// ```
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(non_snake_case)]
pub fn verify_batch<T,I>(
    transcripts: I,
    signatures: &[Signature],
    public_keys: &[PublicKey],
    deduplicate_public_keys: bool,
) -> SignatureResult<()>
where
    T: SigningTranscript, 
    I: IntoIterator<Item=T>,
{
    verify_batch_rng(transcripts, signatures, public_keys, deduplicate_public_keys, rand_hack())  
}

struct NotAnRng;
impl rand_core::RngCore for NotAnRng {
    fn next_u32(&mut self) -> u32 { rand_core::impls::next_u32_via_fill(self) }

    fn next_u64(&mut self) -> u64 { rand_core::impls::next_u64_via_fill(self) }

    /// A no-op function which leaves the destination bytes for randomness unchanged.
    fn fill_bytes(&mut self, dest: &mut [u8]) { ::zeroize::Zeroize::zeroize(dest) }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rand_core::CryptoRng for NotAnRng {}

/// Verify a batch of `signatures` on `messages` with their respective `public_keys`.
///
/// Avoids using system randomness and instead depends entirely upon delinearization.
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(non_snake_case)]
pub fn verify_batch_deterministic<T,I>(
    transcripts: I,
    signatures: &[Signature],
    public_keys: &[PublicKey],
    deduplicate_public_keys: bool,
) -> SignatureResult<()>
where
    T: SigningTranscript, 
    I: IntoIterator<Item=T>,
{
    verify_batch_rng(transcripts, signatures, public_keys, deduplicate_public_keys, NotAnRng)  
}

/// Verify a batch of `signatures` on `messages` with their respective `public_keys`.
/// 
/// Inputs and return agree with `verify_batch` except the user supplies their own random number generator.
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(non_snake_case)]
pub fn verify_batch_rng<T,I,R>(
    transcripts: I,
    signatures: &[Signature],
    public_keys: &[PublicKey],
    deduplicate_public_keys: bool,
    mut rng: R,
) -> SignatureResult<()>
where
    T: SigningTranscript, 
    I: IntoIterator<Item=T>,
    R: RngCore+CryptoRng,
{
    const ASSERT_MESSAGE: &'static str = "The number of messages/transcripts, signatures, and public keys must be equal.";
    assert!(signatures.len() == public_keys.len(), ASSERT_MESSAGE);  // Check transcripts length below

    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use std::vec::Vec;

    use core::iter::once;

    use curve25519_dalek::traits::IsIdentity;
    use curve25519_dalek::traits::VartimeMultiscalarMul;

    // Assumulate public keys, signatures, and transcripts for pseudo-random delinearization scalars
    let mut zs_t = merlin::Transcript::new(b"V-RNG");
    for pk in public_keys {
        zs_t.commit_point(b"",pk.as_compressed());
    }
    for sig in signatures {
        zs_t.append_message(b"",& sig.to_bytes());
    }

    // We might collect here anyways, but right now you cannot have
    //   IntoIterator<Item=T, IntoIter: ExactSizeIterator+TrustedLen>
    // Begin NLL hack
    let mut transcripts = transcripts.into_iter();
    // Compute H(R || A || M) for each (signature, public_key, message) triplet
    let mut hrams: Vec<Scalar> = transcripts.by_ref()
        .zip(0..signatures.len())
        .map( |(mut t,i)| {
            let mut d = [0u8; 16];
            t.witness_bytes_rng(b"", &mut d, &[&[]], NotAnRng);  // Could speed this up using ZeroRng
            zs_t.append_message(b"",&d);

            t.proto_name(b"Schnorr-sig");
            t.commit_point(b"sign:pk",public_keys[i].as_compressed());
            t.commit_point(b"sign:R",&signatures[i].R);
            t.challenge_scalar(b"sign:c")  // context, message, A/public_key, R=rG
        } ).collect();
    assert!(transcripts.next().is_none(), ASSERT_MESSAGE);
    assert!(hrams.len() == public_keys.len(), ASSERT_MESSAGE);

    // Use a random number generator keyed by both the publidc keys,
    // and the system randomn number gnerator 
    let mut csprng = zs_t.build_rng().finalize(&mut rng);
    // Select a random 128-bit scalar for each signature.
    // We may represent these as scalars because we use
    // variable time 256 bit multiplication below. 
    let rnd_128bit_scalar = |_| {
        let mut r = [0u8; 16];
        csprng.fill_bytes(&mut r);
        Scalar::from(u128::from_le_bytes(r))
    };
    let zs: Vec<Scalar> = signatures.iter().map(rnd_128bit_scalar).collect();

    // Compute the basepoint coefficient, ∑ s[i]z[i] (mod l)
    let B_coefficient: Scalar = signatures.iter()
        .map(|sig| sig.s)
        .zip(zs.iter())
        .map(|(s, z)| z * s)
        .sum();
    let B = once(Some(constants::RISTRETTO_BASEPOINT_POINT));

    let Rs = signatures.iter().map(|sig| sig.R.decompress());

    let mut ppks = Vec::new();
    let As = if ! deduplicate_public_keys {
        // Multiply each H(R || A || M) by the random value
        for (hram, z) in hrams.iter_mut().zip(zs.iter()) {
            *hram = &*hram * z; 
        }
        public_keys
    } else {
        // TODO: Actually deduplicate all if deduplicate_public_keys is set?
        ppks.reserve( public_keys.len() );
        // Multiply each H(R || A || M) by the random value
        for i in 0..public_keys.len() {
            let zhram = &hrams[i] * zs[i];
            let j = ppks.len().checked_sub(1);
            if j.is_none() || ppks[j.unwrap()] != public_keys[i] {
                ppks.push(public_keys[i]);
                hrams[ppks.len()-1] = zhram;
            } else {
                hrams[ppks.len()-1] = &hrams[ppks.len()-1] + zhram;                
            }
        }
        hrams.truncate(ppks.len());
        ppks.as_slice()
   }.iter().map(|pk| Some(pk.as_point().clone()));

    // Compute (-∑ z[i]s[i] (mod l)) B + ∑ z[i]R[i] + ∑ (z[i]H(R||A||M)[i] (mod l)) A[i] = 0
    let b = RistrettoPoint::optional_multiscalar_mul(
        once(-B_coefficient).chain(zs.iter().cloned()).chain(hrams),
        B.chain(Rs).chain(As),
    ).map(|id| id.is_identity()).unwrap_or(false);
    // We need not return SigenatureError::PointDecompressionError because
    // the decompression failures occur for R represent invalid signatures.

    if b { Ok(()) } else { Err(SignatureError::EquationFalse) }
}


#[cfg(test)]
mod test {
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use std::vec::Vec;

    use rand::prelude::*; // ThreadRng,thread_rng

    use super::super::*;

    #[cfg(any(feature = "alloc", feature = "std"))]
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
            let mut keypair: Keypair = Keypair::generate_with(&mut csprng);
            if i == 3 || i == 4 { keypair = keypairs[0].clone(); }
            signatures.push(keypair.sign(ctx.bytes(messages[i])));
            keypairs.push(keypair);            
        }
        let mut public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();

        public_keys.swap(1,2);
        let transcripts = messages.iter().map(|m| ctx.bytes(m));
        assert!( verify_batch(transcripts, &signatures[..], &public_keys[..], false).is_err() );
        let transcripts = messages.iter().map(|m| ctx.bytes(m));
        assert!( verify_batch(transcripts, &signatures[..], &public_keys[..], true).is_err() );

        public_keys.swap(1,2);
        let transcripts = messages.iter().map(|m| ctx.bytes(m));
        assert!( verify_batch(transcripts, &signatures[..], &public_keys[..], false).is_ok() );
        let transcripts = messages.iter().map(|m| ctx.bytes(m));
        assert!( verify_batch(transcripts, &signatures[..], &public_keys[..], true).is_ok() );

        signatures.swap(1,2);
        let transcripts = messages.iter().map(|m| ctx.bytes(m));
        assert!( verify_batch(transcripts, &signatures[..], &public_keys[..], false).is_err() );
        let transcripts = messages.iter().map(|m| ctx.bytes(m));
        assert!( verify_batch(transcripts, &signatures[..], &public_keys[..], true).is_err() );
    }
}

