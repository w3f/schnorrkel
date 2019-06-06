// -*- mode: rust; -*-
//
// This file is part of schnorrkel.
// Copyright (c) 2019 Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Schnorr signature contexts and configuration, adaptable to most Schnorr signature schemes.

use core::{cell::RefCell};

use rand::prelude::*;  // {RngCore,thread_rng};

use merlin::{Transcript};

use curve25519_dalek::digest::{Input,FixedOutput,ExtendableOutput,XofReader};
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
/// abstract enough to support conventional hash functions as well.
///
/// We warn however that conventional hash functions do not provide
/// strong enough domain seperation for usage via `&mut` references.
///
/// We fold randomness into witness generation here too, which
/// gives every function that takes a `SigningTranscript` a default
/// argument `rng: impl Rng = thread_rng()` too.
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
    fn witness_scalar(&self, nonce_seeds: &[&[u8]]) -> Scalar {
        let mut scalar_bytes = [0u8; 64];
        self.witness_bytes(&mut scalar_bytes, nonce_seeds);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }

    /// Produce secret witness bytes from the protocol transcript
    /// and any "nonce seeds" kept with the secret keys.
    fn witness_bytes(&self, dest: &mut [u8], nonce_seeds: &[&[u8]]) {
    	self.witness_bytes_rng(dest, nonce_seeds, thread_rng())
    }

    /// Produce secret witness bytes from the protocol transcript
    /// and any "nonce seeds" kept with the secret keys.
    fn witness_bytes_rng<R>(&self, dest: &mut [u8], nonce_seeds: &[&[u8]], rng: R)
    where R: Rng+CryptoRng;
}


/// We delegates any mutable reference to its base type, like `&mut Rng`
/// or similar to `BorrowMut<..>` do, but doing so here simplifies
/// alternative implementations.
impl<T> SigningTranscript for &mut T
where T: SigningTranscript + ?Sized,
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
    fn witness_scalar(&self, nonce_seeds: &[&[u8]]) -> Scalar
        {  (**self).witness_scalar(nonce_seeds)  }
    #[inline(always)]
    fn witness_bytes(&self, dest: &mut [u8], nonce_seeds: &[&[u8]])
        {  (**self).witness_bytes(dest,nonce_seeds)  }
    #[inline(always)]
    fn witness_bytes_rng<R>(&self, dest: &mut [u8], nonce_seeds: &[&[u8]], rng: R)
    where R: Rng+CryptoRng
        {  (**self).witness_bytes_rng(dest,nonce_seeds,rng)  }
}

/// We delegate `SigningTranscript` methods to the corresponding
/// inherent methods of `merlin::Transcript` and implement two
/// witness methods to avoid abrtasting the `merlin::TranscriptRng`
/// machenry.
impl SigningTranscript for Transcript {
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        Transcript::append_message(self, label, bytes)
    }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        Transcript::challenge_bytes(self, label, dest)
    }

    fn witness_bytes_rng<R>(&self, dest: &mut [u8], nonce_seeds: &[&[u8]], mut rng: R)
    where R: Rng+CryptoRng
    {
        let mut br = self.build_rng();
        for ns in nonce_seeds {
            br = br.rekey_with_witness_bytes(b"", ns);
        }
        let mut r = br.finalize(&mut rng);
        r.fill_bytes(dest)
    }
}


/// Schnorr signing context
///
/// We expect users to have seperate `SigningContext`s for each role 
/// that signature play in their protocol.  These `SigningContext`s
/// may be global `lazy_static!`s, or perhaps constants in future.
///
/// To sign a message, apply the appropriate inherent method to create
/// a signature transcript.
///
/// You should use `merlin::Transcript`s directly if you must do
/// anything more complex, like use signatures in larger zero-knoweldge
/// protocols or sign several components but only reveal one later.
///
/// We declare these methods `#[inline(always)]` because rustc does
/// not handle large returns as efficently as one might like.
/// https://github.com/rust-random/rand/issues/817
#[derive(Clone)] // Debug
pub struct SigningContext(Transcript);

/// Initialize a signing context from a static byte string that
/// identifies the signature's role in the larger protocol.
#[inline(always)]
pub fn signing_context(context : &'static [u8]) -> SigningContext {
    SigningContext::new(context)
}

impl SigningContext {
    /// Initialize a signing context from a static byte string that
    /// identifies the signature's role in the larger protocol.
    #[inline(always)]
    pub fn new(context : &'static [u8]) -> SigningContext {
        SigningContext(Transcript::new(context))
    }

    /// Initalize an owned signing transcript on a message provided as a byte array.
    ///
    /// Avoid this method when processing large slices because it
    /// calls `merlin::Transcript::append_message` directly and
    /// `merlin` is designed for domain seperation, not performance.
    #[inline(always)]
    pub fn bytes(&self, bytes: &[u8]) -> Transcript {
        let mut t = self.0.clone();
        t.append_message(b"sign-bytes", bytes);
        t
    }

    /// Initalize an owned signing transcript on a message provided as a hash function with extensible output
    #[inline(always)]
    pub fn xof<D: ExtendableOutput>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 32];
        h.xof_result().read(&mut prehash);
        let mut t = self.0.clone();
        t.append_message(b"sign-XoF", &prehash);
        t
    }

    /// Initalize an owned signing transcript on a message provided as
    /// a hash function with 256 bit output.
    #[inline(always)]
    pub fn hash256<D: FixedOutput<OutputSize=U32>>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 32];
        prehash.copy_from_slice(h.fixed_result().as_slice());
        let mut t = self.0.clone();
        t.append_message(b"sign-256", &prehash);
        t
    }

    /// Initalize an owned signing transcript on a message provided as
    /// a hash function with 512 bit output, usually a gross over kill.
    #[inline(always)]
    pub fn hash512<D: FixedOutput<OutputSize=U64>>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 64];
        prehash.copy_from_slice(h.fixed_result().as_slice());
        let mut t = self.0.clone();
        t.append_message(b"sign-256", &prehash);
        t
    }
}


/// Very simple transcript construction from an arbitrary hash fucntion.
///
/// We provide this transcript type to directly use conventional hash
/// functions with an extensible output mode, meaning `Shake128` and
/// `Blake2x`.  We note that Shak128 might provide no advantage here,
/// since `merlin::Transcript`s already use Keccak, and that no rust
/// implementation for Blake2x currently exists.  
/// 
/// We recommend using `merlin::Transcripts` instead because merlin
/// might provide better domain seperartion than most hash functions.
/// We therefore do not provide conveniences like `signing_context`
/// for this.  
///
/// In `SimpleTranscript` style, we never expose the hash function `H`
/// underlying this type, so that developers cannot circument the
/// domain seperartion provided by our methods.  We do this to make
/// `&mut SimpleTranscript : SigningTranscript` safe.
pub struct SimpleTranscript<H>(H)
where H: Input + ExtendableOutput + Clone;

fn input_bytes<H: Input>(h: &mut H, bytes: &[u8]) {
    let l = bytes.len() as u64;
    h.input(l.to_le_bytes());
    h.input(bytes);
}

impl<H> SimpleTranscript<H>
where H: Input + ExtendableOutput + Clone
{
    /// Create a `SimpleTranscript` from a conventional hash functions with an extensible output mode.
    ///
    /// We intentionally consume and never reexpose the hash function
    /// provided, so that our domain seperation works correctly even
    /// when using `&mut SimpleTranscript : SigningTranscript`.
    #[inline(always)]
    pub fn new(h: H) -> SimpleTranscript<H> { SimpleTranscript(h) }
}

impl<H> SigningTranscript for SimpleTranscript<H>
where H: Input + ExtendableOutput + Clone
{
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.0.input(b"co");
        input_bytes(&mut self.0, label);
        input_bytes(&mut self.0, bytes);
    }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        self.0.input(b"ch");
        input_bytes(&mut self.0, label);
        let l = dest.len() as u64;
        self.0.input(l.to_le_bytes());
        self.0.clone().chain(b"xof").xof_result().read(dest);
    }

    fn witness_bytes_rng<R>(&self, dest: &mut [u8], nonce_seeds: &[&[u8]], mut rng: R)
    where R: Rng+CryptoRng
    {
        let mut h = self.0.clone().chain(b"wb");
        for ns in nonce_seeds {
            input_bytes(&mut h, ns);
        }
        let l = dest.len() as u64;
        h.input(l.to_le_bytes());

        let mut r = [0u8; 32];
        rng.fill_bytes(&mut r);
        h.input(&r);
        h.xof_result().read(dest);
    }
}

/*
impl<H> SimpleTranscript<H>
where H: Input + ExtendableOutput + Clone
{
    fn new(context: &'static [u8]) -> SimpleTranscript<H> {
        SimpleTranscript(h)
    }
}
*/


/// Schnorr signing transcript with the default `ThreadRng` replaced
/// by an arbitrary `CryptoRng`.
///
/// If `ThreadRng` breaks on your platform, or merely if your paranoid,
/// then you might "upgrade" from `ThreadRng` to `OsRng` by using calls
/// like `keypair.sign( attach_rng(t,OSRng::new()) )`.
/// We recommend instead simply fixing `ThreadRng` for your platform
/// however.
///
/// There are also derandomization tricks like
/// `attach_rng(t,ChaChaRng::from_seed([0u8; 32]))`
/// for deterministic signing in tests too.  Although derandomization
/// produces secure signatures, we recommend against doing this in
/// production because we implement protocols like multi-signatures
/// which likely become vulnerabile when derandomized.
pub struct SigningTranscriptWithRng<T,R>
where T: SigningTranscript, R: Rng+CryptoRng
{
	t: T,
	rng: RefCell<R>,
}

impl<T,R> SigningTranscript for SigningTranscriptWithRng<T,R>
where T: SigningTranscript, R: Rng+CryptoRng
{
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8])
        {  self.t.commit_bytes(label, bytes)  }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8])
        {  self.t.challenge_bytes(label, dest)  }

    fn witness_bytes(&self, dest: &mut [u8], nonce_seeds: &[&[u8]])
       {  self.witness_bytes_rng(dest, nonce_seeds, &mut *self.rng.borrow_mut())  }

    fn witness_bytes_rng<RR>(&self, dest: &mut [u8], nonce_seeds: &[&[u8]], rng: RR)
    where RR: Rng+CryptoRng
       {  self.t.witness_bytes_rng(dest,nonce_seeds,rng)  }

}

/// Attach a `CryptoRng` to a `SigningTranscript` to repalce the default `ThreadRng`
///
/// There are tricks like `attach_rng(t,ChaChaRng::from_seed([0u8; 32]))`
/// for deterministic tests.  We warn against doing this in production
/// however because, although such derandomization produces secure Schnorr
/// signatures, we do implement protocols here like multi-signatures which
/// likely become vulnerabile when derandomized.
pub fn attach_rng<T,R>(t: T, rng: R) -> SigningTranscriptWithRng<T,R>
where T: SigningTranscript, R: Rng+CryptoRng
{
    SigningTranscriptWithRng {
        t, rng: RefCell::new(rng)
    }
}

/*
#[cfg(debug_assertions)]
use rand_chacha::ChaChaRng;

/// Attach a `ChaChaRng` to a `Transcript` to repalce the default `ThreadRng`
#[cfg(debug_assertions)]
pub fn attach_chacharng(t: Transcript, seed: [u8; 32]) -> SigningTranscriptWithRng<ChaChaRng> {
    attach_rng(t,ChaChaRng::from_seed(seed))
}
*/


/*
#[cfg(test)]
mod test {
    use rand::prelude::*; // ThreadRng,thread_rng
    use sha3::Shake128;
    use curve25519_dalek::digest::{Input};

}
*/
