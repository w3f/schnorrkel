// -*- mode: rust; -*-
//
// This file is part of schnorrkel.
// Copyright (c) 2019 Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! Schnorr signature contexts and configuration, adaptable
//! to most Schnorr signature schemes.


use rand::prelude::*;  // {RngCore,thread_rng};

use merlin::{Transcript};

use curve25519_dalek::digest::{FixedOutput,ExtendableOutput,XofReader};
use curve25519_dalek::digest::generic_array::typenum::{U32,U64};

use curve25519_dalek::ristretto::{CompressedRistretto}; // RistrettoPoint
use curve25519_dalek::scalar::Scalar;


// === Signing context as transcript === //

/// Schnorr signing transcript
/// 
/// We envision signatures being on messages, but if a signature occurs
/// inside a larger protocol then the signature scheme's internal 
/// transcript may exist before or persist after signing.
/// 
/// In this trait, we provide an interface for Schnorr signature-like
/// constructions that is compatable with `merlin::Transcript`, but
/// abstract enough to support normal hash functions as well.
///
/// We also abstract over owned and borrowed `merlin::Transcript`s,
/// so that simple use cases do not suffer from our support for. 
pub trait SigningTranscript {
    /// Extend transcript with some bytes, shadowed by `merlin::Transcript`.
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]);

    /// Extend transcript with a protocol name
    fn proto_name(&mut self, label: &'static [u8]) {
        self.commit_bytes(b"proto-name", label);
    }

    /// Extend the transcript with a compressed Ristretto point
    fn commit_point(&mut self, label: &'static [u8], compressed: &CompressedRistretto) {
        self.commit_bytes(label, compressed.as_bytes());
    }

    /*
    fn commit_sorted_points<P,S>(&mut self, label: &'static [u8], set: &mut [P])
    where P: Borrow<CompressedRistretto>,
          // S: BorrowMut<[P]>,
    {
        // let set = set.borrow_mut();
        set.sort_unstable_by(
            |a,b| a.borrow().as_bytes()
             .cmp(b.borrow().as_bytes())
        );
        for p in set.iter() {
            self.commit_point(label,p.borrow());
        }
    }
    */

    /// Produce some challenge bytes, shadowed by `merlin::Transcript`.
    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]);

    /// Produce the public challenge scalar `e`.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }

    /// Produce a secret witness scalar `k`, aka nonce, from the protocol
    /// transcript and any "nonce seeds" kept with the secret keys.
    fn witness_scalar<R: Rng+CryptoRng>(&self, nonce_seed: &[u8], extra_nonce_seed: Option<&[u8]>, rng: R) -> Scalar;

    /// Produce secret witness bytes from the protocol transcript
    /// and any "nonce seeds" kept with the secret keys.
    fn witness_bytes<R: Rng+CryptoRng>(&self, dest: &mut [u8], nonce_seed: &[u8], extra_nonce_seed: Option<&[u8]>, rng: R);
}

/// We delegates any mutable reference to its base type, like `&mut Rng`
/// or similar to `BorrowMut<..>` do, but doing so here simplifies 
/// alternative implementations.
impl<'a,T> SigningTranscript for &'a mut T
where T: SigningTranscript + ?Sized
{
    #[inline(always)]
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8])
        {  (**self).commit_bytes(label,bytes)  }
    #[inline(always)]
    fn proto_name(&mut self, label: &'static [u8])
        {  (**self).proto_name(label)  }
    #[inline(always)]
    fn commit_point(&mut self, label: &'static [u8], compressed: &CompressedRistretto)
        {  (**self).commit_point(label, compressed)  }
    #[inline(always)]
    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8])
        {  (**self).challenge_bytes(label,dest)  }
    #[inline(always)]
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar
        {  (**self).challenge_scalar(label)  }
    #[inline(always)]
    fn witness_scalar<R: Rng+CryptoRng>(&self, nonce_seed: &[u8], extra_nonce_seed: Option<&[u8]>, rng: R) -> Scalar
        {  (**self).witness_scalar(nonce_seed,extra_nonce_seed,rng)  }
    #[inline(always)]
    fn witness_bytes<R: Rng+CryptoRng>(&self, dest: &mut [u8], nonce_seed: &[u8], extra_nonce_seed: Option<&[u8]>, rng: R)
        {  (**self).witness_bytes(dest,nonce_seed,extra_nonce_seed,rng)  }
}

/// We delegate `SigningTranscript` methods to the corresponding
/// inherent methods of `merlin::Transcript` and implement two 
/// witness methods to avoid abrtasting the `merlin::TranscriptRng`
/// machenry.
impl SigningTranscript for Transcript {
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        Transcript::commit_bytes(self, label, bytes)
    }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        Transcript::challenge_bytes(self, label, dest)
    }

    fn witness_scalar<R: Rng+CryptoRng>(&self, nonce_seed: &[u8], extra_nonce_seed: Option<&[u8]>, mut rng: R) -> Scalar
    {
        let mut br = self.build_rng()
            .commit_witness_bytes(b"", nonce_seed);
        if let Some(w) = extra_nonce_seed {
            br = br.commit_witness_bytes(b"", w);
        }
        let mut r = br.finalize(&mut rng);
        Scalar::random(&mut r)
    }

    fn witness_bytes<R: Rng+CryptoRng>(&self, dest: &mut [u8], nonce_seed: &[u8], extra_nonce_seed: Option<&[u8]>, mut rng: R)
    {
        let mut br = self.build_rng()
            .commit_witness_bytes(b"", nonce_seed);
        if let Some(w) = extra_nonce_seed {
            br = br.commit_witness_bytes(b"", w);
        }
        let mut r = br.finalize(&mut rng);
        r.fill_bytes(dest)
    }
}


/// Schnorr signing context
///
/// We expect users to seperate `SigningContext`s for each role that
/// signature play in their protocol.  These `SigningContext`s may be
/// global `lazy_static!`s.
///
/// To sign a message, apply the appropriate inherent method to create
/// a signature transcript.
///
/// You should use `merlin::Transcript`s directly if you must do
/// anything more complex, like use signatures in larger zero-knoweldge
/// protocols or sign several components but only reveal one later.
#[derive(Clone)] // Debug
pub struct SigningContext(Transcript);

/// Initialize a signing context from a static byte string that
/// identifies the signature's role in the larger protocol.
pub fn signing_context(context : &'static [u8]) -> SigningContext {
    SigningContext::new(context)
}

impl SigningContext {
    /// Initialize a signing context from a static byte string that
    /// identifies the signature's role in the larger protocol.
    pub fn new(context : &'static [u8]) -> SigningContext {
        SigningContext(Transcript::new(context))
    }

    /// Initalize an owned signing transcript on a message provided as a byte array
    pub fn bytes(&self, bytes: &[u8]) -> Transcript {
        let mut t = self.0.clone();
        t.commit_bytes(b"sign-bytes", bytes);
        t
    }

    /// Initalize an owned signing transcript on a message provided as a hash function with extensible output
    pub fn xof<D: ExtendableOutput>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 32];
        h.xof_result().read(&mut prehash);      
        let mut t = self.0.clone();
        t.commit_bytes(b"sign-XoF", &prehash);
        t
    }

    /// Initalize an owned signing transcript on a message provided as
    /// a hash function with 256 bit output.
    pub fn hash256<D: FixedOutput<OutputSize=U32>>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 32];
        prehash.copy_from_slice(h.fixed_result().as_slice());
        let mut t = self.0.clone();
        t.commit_bytes(b"sign-256", &prehash);
        t
    }

    /// Initalize an owned signing transcript on a message provided as
    /// a hash function with 512 bit output, usually a gross over kill.
    pub fn hash512<D: FixedOutput<OutputSize=U64>>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 64];
        prehash.copy_from_slice(h.fixed_result().as_slice());
        let mut t = self.0.clone();
        t.commit_bytes(b"sign-256", &prehash);
        t
    }
}


/*
#[cfg(test)]
mod test {
    use rand::prelude::*; // ThreadRng,thread_rng
    use sha3::Shake128;
    use curve25519_dalek::digest::{Input};

}
*/
