// -*- mode: rust; -*-
//
// This file is part of schnorrkel.
// Copyright (c) 2019 Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Implementation of a Verifiable Random Function (VRF) using Ristretto points and Schnorr DLEQ proofs.
//!
//! *Warning*  We warn that our VRF construction supports malleable
//! outputs via the `*malleable*` methods.  These are insecure when
//! used in  conjunction with our HDKD provided in dervie.rs.
//! Attackers could translate malleable VRF outputs from one soft subkey 
//! to another soft subkey, gaining early knowledge of the VRF output.
//! We suggest using either non-malleable VRFs or using implicit
//! certificates instead of HDKD when using VRFs.
//!
//! We model the VRF on "Making NSEC5 Practical for DNSSEC" by
//! Dimitrios Papadopoulos, Duane Wessels, Shumon Huque, Moni Naor,
//! Jan Včelák, Leonid Rezyin, andd Sharon Goldberg.
//! https://eprint.iacr.org/2017/099.pdf
//! We note the V(X)EdDSA signature scheme by Trevor Perrin at
//! https://www.signal.org/docs/specifications/xeddsa/#vxeddsa
//! is almost identical to the NSEC5 construction.
//!
//! We support individual signers merging numerous VRF outputs created
//! with the same keypair, which follows the "DLEQ Proofs" and "Batching
//! the Proofs" sections of "Privacy Pass - The Math" by Alex Davidson,
//! https://blog.cloudflare.com/privacy-pass-the-math/#dleqproofs
//! and "Privacy Pass: Bypassing Internet Challenges Anonymously"
//! by Alex Davidson, Ian Goldberg, Nick Sullivan, George Tankersley,
//! and Filippo Valsorda.
//! https://www.petsymposium.org/2018/files/papers/issue3/popets-2018-0026.pdf
//!
//! As noted there, our merging technique's soundness appeals to
//! Theorem 3.17 on page 74 of Ryqan Henry's PhD thesis
//! "Efficient Zero-Knowledge Proofs and Applications"
//! https://uwspace.uwaterloo.ca/bitstream/handle/10012/8621/Henry_Ryan.pdf
//! See also the attack on Peng and Bao’s batch proof protocol in
//! "Batch Proofs of Partial Knowledge" by Ryan Henry and Ian Goldberg
//! https://www.cypherpunks.ca/~iang/pubs/batchzkp-acns.pdf
//!
//! We might reasonably ask if the VRF signer's public key should
//! really be hashed when creating the scalars in `vrfs_merge*`.
//! After all, there is no similar requirement when the values being
//! hashed are BLS public keys in say
//! https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
//! In fact, we expect the public key could be dropped both in
//! Privacy Pass' case, due to using randomness in the messages,
//! and in the VRF case, provided the message depends upon shared
//! randomness created after the public key.  Yet, there are VRF
//! applications outside these two cases, and DLEQ proof applications
//! where the points are not even hashes.  At minimum, we expect
//! hashing the public key prevents malicious signers from choosing
//! their key to cancel out the blinding of a particular point,
//! which might become important in a some anonymity applications.
//! In any case, there is no cost to hashing the public key for VRF
//! applications, but important such an approach cannot yield a
//! verifiable shuffle.
//! TODO: Explain better!
//!
//! We also implement verifier side batching analogous to batched
//! verification of Schnorr signatures, but note this requires an
//! extra curve point, which enlarges the VRF proofs from 64 bytes
//! to 96 bytes.  We provide `shorten_*` methods to produce the
//! non-batchable proof from the batchable proof because doing so
//! is an inherent part of the batch verification anyways.
//! TODO: Security arguments!
//!
//! We do not provide DLEQ proofs optimized for the same signer using
//! multiple public keys because such constructions sound more the
//! domain of zero-knowledge proof libraries.

use core::borrow::Borrow;

#[cfg(any(feature = "alloc", feature = "std"))]
use core::iter::once;

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};
#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

use rand::prelude::*; // ThreadRng,thread_rng
use rand_chacha::ChaChaRng;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

#[cfg(any(feature = "alloc", feature = "std"))]
use curve25519_dalek::traits::VartimeMultiscalarMul;

use merlin::Transcript;

use super::*;
use crate::context::SigningTranscript;
use crate::points::RistrettoBoth;
// use crate::errors::SignatureError;


/// Length of VRF output.
pub const VRF_OUTPUT_LENGTH : usize = 32;

/// Length of the short VRF proof which lacks support for batch verification.
pub const VRF_PROOF_LENGTH : usize = 64;

/// Length of the longer VRF proof which supports batch verification.
pub const VRF_PROOF_BATCHABLE_LENGTH : usize = 96;

/// `SigningTranscript` helper trait that manages VRF output malleability.
///
/// In short, `VRFSigningTranscript` acts like a default argument
/// `malleabe : bool = false` for every mathod that uses it instead of
/// `SigningTranscript`.
pub trait VRFSigningTranscript {
    /// Real underlying `SigningTranscript`
    type T: SigningTranscript;
    /// Return the underlying `SigningTranscript` after addressing
    /// VRF output malleability, usually by making it non-malleable,
    fn transcript_with_malleability_addressed(self, publickey: &PublicKey) -> Self::T;
}

impl<T> VRFSigningTranscript for T where T: SigningTranscript {
    type T = T;
    #[inline(always)]
    fn transcript_with_malleability_addressed(mut self, publickey: &PublicKey) -> T {
        self.commit_point(b"vrf-nm-pk", publickey.as_compressed());        
        // publickey.make_transcript_nonmalleable(&mut self);
        self
    }
}

/// VRF SigningTranscript for malleable VRF ouputs.
///
/// *Warning*  We caution that malleable VRF outputs are insecure when
/// used in conjunction with HDKD, as provided in dervie.rs. 
/// Attackers could translate malleable VRF outputs from one soft subkey 
/// to another soft subkey, gaining early knowledge of the VRF output.
/// We think most VRF applicaitons for which HDKH soudns suitable
/// benefit from using implicit certificates insead of HDKD anyways,
/// which should also be secure in combination with HDKH.
/// We always use non-malleable VRF inputs in our convenience methods.
#[derive(Clone)]
pub struct Malleable<T: SigningTranscript>(pub T);
impl<T> VRFSigningTranscript for Malleable<T> where T: SigningTranscript {
    type T = T;
    #[inline(always)]
    fn transcript_with_malleability_addressed(self, _publickey: &PublicKey) -> T { self.0 }
}


/// Create a malleable VRF input point by hashing a transcript to a point.
///
/// *Warning*  We caution that malleable VRF inputs are insecure when
/// used in conjunction with HDKD, as provided in dervie.rs. 
/// Attackers could translate malleable VRF outputs from one soft subkey 
/// to another soft subkey, gaining early knowledge of the VRF output.
/// We think most VRF applicaitons for which HDKH soudns suitable
/// benefit from using implicit certificates insead of HDKD anyways,
/// which should also be secure in combination with HDKH.
/// We always use non-malleable VRF inputs in our convenience methods.
pub fn vrf_malleable_hash<T: SigningTranscript>(mut t: T) -> RistrettoBoth {
    let mut b = [0u8; 64];
    t.challenge_bytes(b"VRFHash", &mut b);
    RistrettoBoth::from_point(RistrettoPoint::from_uniform_bytes(&b))
}

impl PublicKey {
    /// Create a non-malleable VRF input point by hashing a transcript to a point.
    pub fn vrf_hash<T>(&self, t: T) -> RistrettoBoth
    where T: VRFSigningTranscript {
        vrf_malleable_hash(t.transcript_with_malleability_addressed(self))
    }

    /// Pair a non-malleable VRF output with the hash of the given transcript.
    pub fn vrf_attach_hash<T>(&self, output: VRFOutput, t: T) -> SignatureResult<VRFInOut>
    where T: VRFSigningTranscript {
        output.attach_input_hash(self,t)
    }
}

/// VRF output, possibly unverified.
///
/// Internally, we keep both `RistrettoPoint` and `CompressedRistretto`
/// forms using `RistrettoBoth`.
///
/// We'd actually love to statically distinguish here between inputs
/// and outputs, as well as whether outputs were verified, but doing
/// so would disrupt our general purpose DLEQ proof mechanism, so
/// users must be responcible for this themselves.  We do however
/// consume by value in actual output methods, and do not implement
/// `Copy`, as a reminder that VRF outputs should only be used once
/// and should be checked before usage.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VRFOutput(pub [u8; PUBLIC_KEY_LENGTH]);

impl VRFOutput {
    const DESCRIPTION: &'static str =
        "A Ristretto Schnorr VRF output represented as a 32-byte Ristretto compressed point";

    /// Convert this VRF output to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; VRF_OUTPUT_LENGTH] {
        self.0
    }

    /// View this secret key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; VRF_OUTPUT_LENGTH] {
        &self.0
    }

    /// Construct a `VRFOutput` from a slice of bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<VRFOutput> {
        if bytes.len() != VRF_OUTPUT_LENGTH {
            return Err(SignatureError::BytesLengthError {
                name: "VRFOutput",
                description: VRFOutput::DESCRIPTION,
                length: VRF_OUTPUT_LENGTH
            });
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);
        Ok(VRFOutput(bits))
    }

    /// Pair a non-malleable VRF output with the hash of the given transcript.
    pub fn attach_input_hash<T>(&self, public: &PublicKey, t: T) -> SignatureResult<VRFInOut>
	where T: VRFSigningTranscript {
        let input = public.vrf_hash(t);
        let output = RistrettoBoth::from_bytes_ser("VRFOutput", VRFOutput::DESCRIPTION, &self.0)?;
        Ok(VRFInOut { input, output })
    }
}

serde_boilerplate!(VRFOutput);

/// VRF input and output paired together, possibly unverified.
///
/// Internally, we keep both `RistrettoPoint` and `CompressedRistretto`
/// forms using `RistrettoBoth`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VRFInOut {
    /// VRF input point
    pub input: RistrettoBoth,
    /// VRF output point
    pub output: RistrettoBoth,
}

impl SecretKey {
    /// Evaluate the VRF-like multiplication on an uncompressed point,
    /// probably not useful in this form.
    pub fn vrf_create_from_point(&self, input: RistrettoBoth) -> VRFInOut {
        let output = RistrettoBoth::from_point(&self.key * input.as_point());
        VRFInOut { input, output }
    }

    /// Evaluate the VRF-like multiplication on a compressed point,
    /// useful for proving key exchanges, OPRFs, or sequential VRFs.
    pub fn vrf_create_from_compressed_point(&self, input: &VRFOutput) -> SignatureResult<VRFInOut> {
        let input = RistrettoBoth::from_compressed(CompressedRistretto(input.0)) ?;
        Ok(self.vrf_create_from_point(input))
    }
}

impl Keypair {
    /// Evaluate the VRF on the given transcript.
    pub fn vrf_create_hash<T: VRFSigningTranscript>(&self, t: T) -> VRFInOut {
        self.secret.vrf_create_from_point(self.public.vrf_hash(t))
    }
}

impl VRFInOut {
    /// VRF output point bytes for serialization.
    pub fn as_output_bytes(&self) -> &[u8; 32] {
        self.output.as_compressed().as_bytes()
    }

    /// VRF output point bytes for serialization.
    pub fn to_output(&self) -> VRFOutput {
        VRFOutput(self.output.as_compressed().to_bytes())
    }

    /// Commit VRF input and output to a transcript.
    ///
    /// We commit both the input and output to provide the 2Hash-DH
    /// construction from Theorem 2 on page 32 in appendex C of
    /// ["Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain"](https://eprint.iacr.org/2017/573.pdf)
    /// by Bernardo David, Peter Gazi, Aggelos Kiayias, and Alexander Russell.
    ///
    /// We use this construction both for the VRF usage methods
    /// `VRFInOut::make_*` as well as for signer side batching.
    pub fn commit<T: SigningTranscript>(&self, t: &mut T) {
        t.commit_point(b"vrf-in", self.input.as_compressed());
        t.commit_point(b"vrf-out", self.output.as_compressed());
    }

    /// Raw bytes output from the VRF.
    ///
    /// If you are not the signer then you must verify the VRF before calling this method.
    ///
    /// If called with distinct contexts then outputs should be independent.
    ///
    /// We incorporate both the input and output to provide the 2Hash-DH
    /// construction from Theorem 2 on page 32 in appendex C of
    /// ["Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain"](https://eprint.iacr.org/2017/573.pdf)
    /// by Bernardo David, Peter Gazi, Aggelos Kiayias, and Alexander Russell.
    pub fn make_bytes<B: Default + AsMut<[u8]>>(&self, context: &'static [u8]) -> B {
        let mut t = Transcript::new(context);
        self.commit(&mut t);
        let mut seed = B::default();
        t.challenge_bytes(b"", seed.as_mut());
        seed
    }

    /// VRF output converted into any `SeedableRng`.
    ///
    /// If you are not the signer then you must verify the VRF before calling this method.
    ///
    /// We expect most users would prefer the less generic `VRFInOut::make_chacharng` method.
    pub fn make_rng<R: SeedableRng>(&self, context: &'static [u8]) -> R {
        R::from_seed(self.make_bytes::<R::Seed>(context))
    }

    /// VRF output converted into a `ChaChaRng`.
    ///
    /// If you are not the signer then you must verify the VRF before calling this method.
    ///
    /// If called with distinct contexts then outputs should be independent.
    /// Independent output streams are available via `ChaChaRng::set_stream` too.
    ///
    /// We incorporate both the input and output to provide the 2Hash-DH
    /// construction from Theorem 2 on page 32 in appendex C of
    /// ["Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain"](https://eprint.iacr.org/2017/573.pdf)
    /// by Bernardo David, Peter Gazi, Aggelos Kiayias, and Alexander Russell.
    pub fn make_chacharng(&self, context: &'static [u8]) -> ChaChaRng {
        self.make_rng::<ChaChaRng>(context)
    }

    /// VRF output converted into Merlin's Keccek based `Rng`.
    ///
    /// If you are not the signer then you must verify the VRF before calling this method.
    ///
    /// We think this might be marginally slower than `ChaChaRng`
    /// when considerable output is required, but it should reduce
    /// the final linked binary size slightly, and improves domain
    /// separation.
    #[inline(always)]
    pub fn make_merlin_rng(&self, context: &'static [u8]) -> merlin::TranscriptRng {
        // Very insecure hack except for our commit_witness_bytes below
        struct ZeroFakeRng;
        impl ::rand::RngCore for ZeroFakeRng {
            fn next_u32(&mut self) -> u32 {  panic!()  }
            fn next_u64(&mut self) -> u64 {  panic!()  }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                for i in dest.iter_mut() {  *i = 0;  }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl ::rand::CryptoRng for ZeroFakeRng {}

        let mut t = Transcript::new(context);
        self.commit(&mut t);
        t.build_rng().finalize(&mut ZeroFakeRng)
    }
}

fn challenge_scalar_128<T: SigningTranscript>(mut t: T) -> Scalar {
    let mut s = [0u8; 16];
    t.challenge_bytes(b"", &mut s);
    Scalar::from(u128::from_le_bytes(s))
}

impl PublicKey {
    /// Merge VRF input and output pairs from the same signer,
    /// using constant time arithmetic.
    ///
    /// There is sadly no constant time 128 bit multiplication in dalek,
    /// making this variant somewhat slower than necessary.  It should
    /// only impact signers in niche scenarios however, so this slower
    /// variant should normally be unnecessary.
    ///
    /// TODO: Add constant time 128 bit batched multiplication to dalek.
    /// TODO: Is rand_chacha's `gen::<u128>()` standardizable enough to
    /// prefer it over merlin for the output?  
    pub fn vrfs_merge<B>(&self, ps: &[B]) -> VRFInOut
    where
        B: Borrow<VRFInOut>,
    {
        let mut t = ::merlin::Transcript::new(b"MergeVRFs");
        t.commit_point(b"pk", self.as_compressed());
        for p in ps.iter() {
            p.borrow().commit(&mut t);
        }

        let mut input = ps[0].borrow().input.as_point().clone();
        let mut output = ps[0].borrow().output.as_point().clone();
        for p in ps.iter().skip(1).map(|p| p.borrow()) {
            let mut t0 = t.clone();
            p.commit(&mut t0);
            let z = challenge_scalar_128(t0);
            input += &z * p.input.as_point();
            output += &z * p.output.as_point();
        }

        VRFInOut {
            input: RistrettoBoth::from_point(input),
            output: RistrettoBoth::from_point(output),
        }
    }

    /// Merge VRF input and output pairs from the same signer,
    /// using variable time arithmetic
    ///
    /// You should use this variant when verifying VRF proofs batched
    /// by the singer.  You could usually use this variant even when
    /// producing proofs, provided the set being signed is not secret.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_merge_vartime<B>(&self, ps: &[B]) -> VRFInOut
    where
        B: Borrow<VRFInOut>,
    {
        let mut t = ::merlin::Transcript::new(b"MergeVRFs");
        t.commit_point(b"pk", self.as_compressed());
        for p in ps.iter() {
            p.borrow().commit(&mut t);
        }

        let zs: Vec<Scalar> = ps.iter().skip(1)
            .map(|p| {
                let mut t0 = t.clone();
                p.borrow().commit(&mut t0);
                challenge_scalar_128(t0)
            }).collect();
        let one = Scalar::one();
        let zf = || once(&one).chain(zs.iter());

        VRFInOut {
            input: RistrettoBoth::from_point(RistrettoPoint::vartime_multiscalar_mul(
                zf(),
                ps.iter().map(|p| p.borrow().input.as_point()),
            )),
            output: RistrettoBoth::from_point(RistrettoPoint::vartime_multiscalar_mul(
                zf(),
                ps.iter().map(|p| p.borrow().output.as_point()),
            )),
        }
    }
}

/// Short proof of correctness for associated VRF output,
/// for which no batched verification works.
#[derive(Debug, Clone, PartialEq, Eq)] // PartialOrd, Ord, Hash
pub struct VRFProof {
    /// Challenge
    c: Scalar,
    /// Schnorr proof
    s: Scalar,
}

impl VRFProof {
    const DESCRIPTION : &'static str = "A Ristretto Schnorr VRF proof without batch verification support, which consists of two scalars, making it 64 bytes.";

    /// Convert this `VRFProof` to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; VRF_PROOF_LENGTH] {
        let mut bytes = [0u8; VRF_PROOF_LENGTH];

        bytes[..32].copy_from_slice(&self.c.as_bytes()[..]);
        bytes[32..].copy_from_slice(&self.s.as_bytes()[..]);
        bytes
    }

    /// Construct a `VRFProof` from a slice of bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<VRFProof> {
        if bytes.len() != VRF_PROOF_LENGTH {
            return Err(SignatureError::BytesLengthError {
                name: "VRFProof",
                description: VRFProof::DESCRIPTION,
                length: VRF_PROOF_LENGTH
            });
        }
        let mut c: [u8; 32] = [0u8; 32];
        let mut s: [u8; 32] = [0u8; 32];

        c.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);

        let c = Scalar::from_canonical_bytes(c).ok_or(SignatureError::ScalarFormatError) ?;
        let s = Scalar::from_canonical_bytes(s).ok_or(SignatureError::ScalarFormatError) ?;
        Ok(VRFProof { c, s })
    }
}

serde_boilerplate!(VRFProof);

/// Longer proof of correctness for associated VRF output,
/// which supports batching.
#[derive(Debug, Clone, PartialEq, Eq)] // PartialOrd, Ord, Hash
#[allow(non_snake_case)]
pub struct VRFProofBatchable {
    /// Our nonce R = r G to permit batching the first verification equation
    R: CompressedRistretto,
    /// Our input hashed and raised to r to permit batching the second verification equation
    Hr: CompressedRistretto,
    /// Schnorr proof
    s: Scalar,
}

impl VRFProofBatchable {
    const DESCRIPTION : &'static str = "A Ristretto Schnorr VRF proof that supports batch verification, which consists of two Ristretto compressed points and one scalar, making it 96 bytes.";

    /// Convert this `VRFProofBatchable` to a byte array.
	#[allow(non_snake_case)]
    #[inline]
    pub fn to_bytes(&self) -> [u8; VRF_PROOF_BATCHABLE_LENGTH] {
        let mut bytes = [0u8; VRF_PROOF_BATCHABLE_LENGTH];

        bytes[0..32].copy_from_slice(&self.R.as_bytes()[..]);
        bytes[32..64].copy_from_slice(&self.Hr.as_bytes()[..]);
        bytes[64..96].copy_from_slice(&self.s.as_bytes()[..]);
        bytes
    }

    /// Construct a `VRFProofBatchable` from a slice of bytes.
	#[allow(non_snake_case)]
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<VRFProofBatchable> {
        if bytes.len() != VRF_PROOF_BATCHABLE_LENGTH {
            return Err(SignatureError::BytesLengthError {
                name: "VRFProofBatchable",
                description: VRFProofBatchable::DESCRIPTION,
                length: VRF_PROOF_BATCHABLE_LENGTH,
            });
        }
        let mut R: [u8; 32] = [0u8; 32];
        let mut Hr: [u8; 32] = [0u8; 32];
        let mut s: [u8; 32] = [0u8; 32];

        R.copy_from_slice(&bytes[0..32]);
        Hr.copy_from_slice(&bytes[32..64]);
        s.copy_from_slice(&bytes[64..96]);

        let s = Scalar::from_canonical_bytes(s).ok_or(SignatureError::ScalarFormatError) ?;
        Ok(VRFProofBatchable { R: CompressedRistretto(R), Hr: CompressedRistretto(Hr), s })
    }

    /// Return the shortened `VRFProof` for retransmitting in not batched situations
    #[allow(non_snake_case)]
    pub fn shorten_dleq<T>(&self, mut t: T, public: &PublicKey, p: &VRFInOut) -> VRFProof
    where T: SigningTranscript,
    {
        t.proto_name(b"DLEQProof");
        // t.commit_point(b"g",constants::RISTRETTO_BASEPOINT_TABLE.basepoint().compress());
        t.commit_point(b"h", p.input.as_compressed());

        t.commit_point(b"R=g^r", &self.R);
        t.commit_point(b"h^r", &self.Hr);

        t.commit_point(b"pk", public.as_compressed());
        t.commit_point(b"h^sk", p.output.as_compressed());

        VRFProof {
            c: t.challenge_scalar(b""), // context, message, A/public_key, R=rG
            s: self.s,
        }
    }

    /// Return the shortened `VRFProof` for retransmitting in non-batched situations
    ///
    /// TODO: Avoid the error path here by avoiding decompressing,
    /// either locally here, or more likely by decompressing
    /// `VRFOutput` in deserialization.
    pub fn shorten_vrf<T>( &self, public: &PublicKey, t: T, out: &VRFOutput)
     -> SignatureResult<VRFProof>
    where T: VRFSigningTranscript,
	{
        let p = out.attach_input_hash(public,t) ?; // Avoidable errors if decompressed earlier
        let t0 = Transcript::new(b"VRF");  // We have context in t and another hear confuses batching
        Ok(self.shorten_dleq(t0, public, &p))
    }
}

serde_boilerplate!(VRFProofBatchable);

impl Keypair {
    /// Produce DLEQ proof.
    ///
    /// We mutate `points` by multiplying every point by `self.secret`
    /// and produce a proof that this multiplication was done correctly.
    #[allow(non_snake_case)]
    pub fn dleq_proove<T>(&self, mut t: T, p: &VRFInOut) -> (VRFProof, VRFProofBatchable)
    where
        T: SigningTranscript,
    {
        t.proto_name(b"DLEQProof");
        // t.commit_point(b"g",constants::RISTRETTO_BASEPOINT_TABLE.basepoint().compress());
        t.commit_point(b"h", p.input.as_compressed());

        // We compute R after adding pk and all h.
        let mut r = t.witness_scalar(&[&self.secret.nonce]);
        let R = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        t.commit_point(b"R=g^r", &R);

        let Hr = (&r * p.input.as_point()).compress();
        t.commit_point(b"h^r", &Hr);

        t.commit_point(b"pk", self.public.as_compressed());
        // We add h^sk last to save an allocation if we ever need to hash multiple h together.
        t.commit_point(b"h^sk", p.output.as_compressed());

        let c = t.challenge_scalar(b""); // context, message, A/public_key, R=rG
        let s = &r - &(&c * &self.secret.key);

        // TODO: Check assembler to see if this improves anything 
        // TODO: Replace with Zeroize but ClearOnDrop does not work with std
        #[cfg(any(feature = "std"))]
        ::clear_on_drop::clear::Clear::clear(&mut r);

        (VRFProof { c, s }, VRFProofBatchable { R, Hr, s })
    }

    /// Run VRF on one single input transcript, producing the outpus
    /// and correspodning short proof.
    ///
    /// There are schemes like Ouroboros Praos in which nodes evaluate
    /// VRFs repeatedly until they win some contest.  In these case,
    /// you should probably use vrf_sign_n_check to gain access to the
    /// `VRFInOut` from `vrf_create_hash` first, and then avoid computing
    /// the proof whenever you do not win. 
    pub fn vrf_sign<T>(&self, t: T) -> (VRFInOut, VRFProof, VRFProofBatchable)
    where T: VRFSigningTranscript,
    {
        let p = self.vrf_create_hash(t);
        let t0 = Transcript::new(b"VRF"); // We have context in t and another hear confuses batching
        let (proof, proof_batchable) = self.dleq_proove(t0, &p);
        (p, proof, proof_batchable)
    }

    /// Run VRF on one single input transcript, producing the outpus
    /// and correspodning short proof only if the result first passes
    /// some check.
    ///
    /// There are schemes like Ouroboros Praos in which nodes evaluate
    /// VRFs repeatedly until they win some contest.  In these case,
    /// you might use this function to short circuit computing the full
    /// proof.
    pub fn vrf_sign_after_check<T,F>(&self, t: T, mut check: F)
     -> Option<(VRFInOut, VRFProof, VRFProofBatchable)>
	where T: VRFSigningTranscript,
          F: FnMut(&VRFInOut) -> bool
    {
        let p = self.vrf_create_hash(t);
        if ! check(&p) { return None; }
        let t0 = Transcript::new(b"VRF"); // We have context in t and another hear confuses batching
        let (proof, proof_batchable) = self.dleq_proove(t0, &p);
        Some((p, proof, proof_batchable))
    }

    /// Run VRF on several input transcripts, producing their outputs
    /// and a common short proof.
    ///
    /// We merge the VRF outputs using variable time arithmetic, so
    /// if even the hash of the message being signed is sensitive then
    /// you might reimplement some constant time variant.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_sign<T, I>(&self, ts: I) -> (Box<[VRFInOut]>, VRFProof, VRFProofBatchable)
    where
        T: VRFSigningTranscript,
        I: IntoIterator<Item = T>,
    {
        let ps = ts.into_iter()
            .map(|t| self.vrf_create_hash(t))
            .collect::<Vec<VRFInOut>>();
        let p = self.public.vrfs_merge_vartime(&ps);
        let t0 = Transcript::new(b"VRF");
        let (proof, proof_batchable) = self.dleq_proove(t0, &p);
        (ps.into_boxed_slice(), proof, proof_batchable)
    }
}

impl PublicKey {
    /// Verify DLEQ proof that `p.output = s * p.input` where `self`
    /// `s` times the basepoint.
    ///
    /// We return an enlarged `VRFProofBatchable` instead of just true,
    /// so that verifiers can forward batchable proofs.
    ///
    /// In principle, one might provide "blindly verifiable" VRFs that
    /// avoid requiring `self` here, but naively such constructions
    /// risk the same flaws as DLEQ based blind signatures, and this
    /// version exploits the slightly faster basepoint arithmetic.
    #[allow(non_snake_case)]
    pub fn dleq_verify<T>(
        &self,
        mut t: T,
        p: &VRFInOut,
        proof: &VRFProof,
    ) -> SignatureResult<VRFProofBatchable>
    where
        T: SigningTranscript,
    {
        t.proto_name(b"DLEQProof");
        // t.commit_point(b"g",constants::RISTRETTO_BASEPOINT_TABLE.basepoint().compress());
        t.commit_point(b"h", p.input.as_compressed());

        // We recompute R aka u from the proof
        // let R = (&proof.c * self.as_point()) + (&proof.s * &constants::RISTRETTO_BASEPOINT_TABLE);
        let R = RistrettoPoint::vartime_double_scalar_mul_basepoint(
            &proof.c,
            self.as_point(),
            &proof.s,
        ).compress();
        t.commit_point(b"R=g^r", &R);

        // We also recompute h^r aka u using the proof
        #[cfg(not(any(feature = "alloc", feature = "std")))]
        let Hr = (&proof.c * p.output.as_point()) + (&proof.s * p.input.as_point());

        // TODO: Verify if this is actually faster using benchmarks
        #[cfg(any(feature = "alloc", feature = "std"))]
        let Hr = RistrettoPoint::vartime_multiscalar_mul(
            &[proof.c, proof.s],
            &[*p.output.as_point(), *p.input.as_point()],
        );

        let Hr = Hr.compress();
        t.commit_point(b"h^r", &Hr);

        t.commit_point(b"pk", self.as_compressed());
        // We add h^sk last to save an allocation if we ever need to hash multiple h together.
        t.commit_point(b"h^sk", p.output.as_compressed());

        // We need not check that h^pk lies on the curve because Ristretto ensures this.
        let VRFProof { c, s } = *proof;
        if c == t.challenge_scalar(b"") {
            Ok(VRFProofBatchable { R, Hr, s }) // Scalar: Copy ?!?
        } else {
            Err(SignatureError::EquationFalse)
        }
    }

    /// Verify VRF proof for one single input transcript and corresponding output.
    pub fn vrf_verify<T: VRFSigningTranscript>(
        &self,
        t: T,
        out: &VRFOutput,
        proof: &VRFProof,
    ) -> SignatureResult<(VRFInOut, VRFProofBatchable)> {
        let p = out.attach_input_hash(self,t)?;
        let t0 = Transcript::new(b"VRF"); // We have context in t and another hear breaks batching
        let proof_batchable = self.dleq_verify(t0, &p, proof)?;
        Ok((p, proof_batchable))
    } 

    /// Verify a common VRF short proof for several input transcripts and corresponding outputs.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_verify<T, I, O>(
        &self,
        transcripts: I,
        outs: &[O],
        proof: &VRFProof,
    ) -> SignatureResult<(Box<[VRFInOut]>, VRFProofBatchable)>
    where
        T: VRFSigningTranscript,
        I: IntoIterator<Item = T>,
        O: Borrow<VRFOutput>,
    {
        let mut ts = transcripts.into_iter();
        let ps = ts.by_ref().zip(outs)
            .map(|(t, out)| out.borrow().attach_input_hash(self,t))
            .collect::<SignatureResult<Vec<VRFInOut>>>()?;
        assert!(ts.next().is_none(), "Too few VRF outputs for VRF inputs.");
        assert!(
            ps.len() == outs.len(),
            "Too few VRF inputs for VRF outputs."
        );
        let p = self.vrfs_merge_vartime(&ps[..]);
        let t0 = Transcript::new(b"VRF"); // We have context in t and another hear breaks batching
        let proof_batchable = self.dleq_verify(t0, &p, proof)?;
        Ok((ps.into_boxed_slice(), proof_batchable))
    }
}

/// Batch verify DLEQ proofs where the public keys were held by
/// different parties.
///
/// We first reconstruct the `c`s present in the `VRFProof`s but absent
/// in the `VRFProofBatchable`s, using `shorten_dleq`.  We then verify
/// the `R` and `Hr` components of the `VRFProofBatchable`s using the
/// two equations a normal verification uses to discover them.
/// We do this by delinearizing both verification equations with
/// random numbers.
///
/// TODO: Assess when the two verification equations should be
/// combined, presumably by benchmarking both forms.  At smaller batch
/// sizes then we should clearly benefit form the combined form, but
/// bany combination doubles the scalar by scalar multiplicications
/// and hashing, so large enough batch verifications should favor two
/// seperate calls.
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(non_snake_case)]
pub fn dleq_verify_batch(
    ps: &[VRFInOut],
    proofs: &[VRFProofBatchable],
    public_keys: &[PublicKey],
) -> SignatureResult<()> {
    use curve25519_dalek::traits::IsIdentity;

    const ASSERT_MESSAGE: &'static str = "The number of messages/transcripts / input points, output points, proofs, and public keys must be equal.";
    assert!(ps.len() == proofs.len(), ASSERT_MESSAGE);
    assert!(proofs.len() == public_keys.len(), ASSERT_MESSAGE);

    let mut rng = rand::prelude::thread_rng();

    // Select a random 128-bit scalar for each signature.
    // We may represent these as scalars because we use
    // variable time 256 bit multiplication below.
    let zz: Vec<Scalar> = proofs.iter()
        .map(|_| Scalar::from(rng.gen::<u128>()))
        .collect();

    let z_s: Vec<Scalar> = zz.iter().zip(proofs)
        .map(|(z, proof)| z * proof.s)
        .collect();

    // Compute the basepoint coefficient, ∑ s[i]z[i] (mod l)
    let B_coefficient: Scalar = z_s.iter().sum();

    let t0 = Transcript::new(b"VRF");
    let z_c: Vec<Scalar> = zz.iter().enumerate()
        .map( |(i, z)| z * proofs[i].shorten_dleq(t0.clone(), &public_keys[i], &ps[i]).c )
        .collect();

    // Compute (∑ z[i] s[i] (mod l)) B + ∑ (z[i] c[i] (mod l)) A[i] - ∑ z[i] R[i] = 0
    let mut b = RistrettoPoint::optional_multiscalar_mul(
        zz.iter().map(|z| -z)
            .chain(z_c.iter().cloned())
            .chain(once(B_coefficient)),
        proofs.iter().map(|proof| proof.R.decompress())
            .chain(public_keys.iter().map(|pk| Some(*pk.as_point())))
            .chain(once(Some(constants::RISTRETTO_BASEPOINT_POINT))),
    ).map(|id| id.is_identity()).unwrap_or(false);

    // Compute (∑ z[i] s[i] (mod l)) Input[i] + ∑ (z[i] c[i] (mod l)) Output[i] - ∑ z[i] Hr[i] = 0
    b &= RistrettoPoint::optional_multiscalar_mul(
        zz.iter().map(|z| -z)
            .chain(z_c)
            .chain(z_s),
        proofs.iter().map(|proof| proof.Hr.decompress())
            .chain(ps.iter().map(|p| Some(*p.output.as_point())))
            .chain(ps.iter().map(|p| Some(*p.input.as_point()))),
    ).map(|id| id.is_identity()).unwrap_or(false);

    if b { Ok(()) } else { Err(SignatureError::EquationFalse) }
}

/// Batch verify VRFs by different signers
///
///
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn vrf_verify_batch<T, I>(
    transcripts: I,
    outs: &[VRFOutput],
    proofs: &[VRFProofBatchable],
    publickeys: &[PublicKey],
) -> SignatureResult<Box<[VRFInOut]>>
where
    T: VRFSigningTranscript,
    I: IntoIterator<Item = T>,
{
    let mut ts = transcripts.into_iter();
    let ps = ts.by_ref()
        .zip(publickeys)
        .zip(outs)
        .map(|((t, pk), out)| out.attach_input_hash(pk,t))
        .collect::<SignatureResult<Vec<VRFInOut>>>()?;
    assert!(ts.next().is_none(), "Too few VRF outputs for VRF inputs.");
    assert!(
        ps.len() == outs.len(),
        "Too few VRF inputs for VRF outputs."
    );
    if dleq_verify_batch(&ps[..], proofs, publickeys).is_ok() {
        Ok(ps.into_boxed_slice())
    } else {
        Err(SignatureError::EquationFalse)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use std::vec::Vec;

    use super::*;
    use rand::prelude::*;

    #[test]
    fn vrf_single() {
        let keypair1 = Keypair::generate(&mut thread_rng());

        let ctx = signing_context(b"yo!");
        let msg = b"meow";
        let (io1, proof1, proof1batchable) = keypair1.vrf_sign(ctx.bytes(msg));
        let out1 = &io1.to_output();
        assert_eq!(
            proof1,
            proof1batchable
                .shorten_vrf(&keypair1.public, ctx.bytes(msg), &out1)
                .unwrap(),
            "Oops `shorten_vrf` failed"
        );
        let (io1too, proof1too) = keypair1.public.vrf_verify(ctx.bytes(msg), &out1, &proof1)
            .expect("Correct VRF verification failed!");
        assert_eq!(
            io1too, io1,
            "Output differs between signing and verification!"
        );
        assert_eq!(
            proof1batchable, proof1too,
            "VRF verification yielded incorrect batchable proof"
        );
        assert_eq!(
            keypair1.vrf_sign(ctx.bytes(msg)).0,
            io1,
            "Rerunning VRF gave different output"
        );

        assert!(
            keypair1.public.vrf_verify(ctx.bytes(b"not meow"), &out1, &proof1).is_err(),
            "VRF verification with incorrect message passed!"
        );

        let keypair2 = Keypair::generate(&mut thread_rng());
        assert!(
            keypair2.public.vrf_verify(ctx.bytes(msg), &out1, &proof1).is_err(),
            "VRF verification with incorrect signer passed!"
        );
    }

    #[test]
    fn vrf_malleable() {
        let keypair1 = Keypair::generate(&mut thread_rng());

        let ctx = signing_context(b"yo!");
        let msg = b"meow";
        let (io1, proof1, proof1batchable) = keypair1.vrf_sign(Malleable(ctx.bytes(msg)));
        let out1 = &io1.to_output();
        assert_eq!(
            proof1,
            proof1batchable.shorten_vrf(&keypair1.public, Malleable(ctx.bytes(msg)), &out1).unwrap(),
            "Oops `shorten_vrf` failed"
        );
        let (io1too, proof1too) = keypair1
            .public.vrf_verify(Malleable(ctx.bytes(msg)), &out1, &proof1)
            .expect("Correct VRF verification failed!");
        assert_eq!(
            io1too, io1,
            "Output differs between signing and verification!"
        );
        assert_eq!(
            proof1batchable, proof1too,
            "VRF verification yielded incorrect batchable proof"
        );
        assert_eq!(
            keypair1.vrf_sign(Malleable(ctx.bytes(msg))).0,
            io1,
            "Rerunning VRF gave different output"
        );
        assert!(
            keypair1.public.vrf_verify(Malleable(ctx.bytes(b"not meow")), &out1, &proof1).is_err(),
            "VRF verification with incorrect message passed!"
        );

        let keypair2 = Keypair::generate(&mut thread_rng());
        assert!(
            keypair2.public.vrf_verify(Malleable(ctx.bytes(msg)), &out1, &proof1).is_err(),
            "VRF verification with incorrect signer passed!"
        );
        let (io2, _proof2, _proof2batchable) = keypair2.vrf_sign(Malleable(ctx.bytes(msg)));
        let out2 = &io2.to_output();

        // Verified key exchange, aka sequential two party VRF.
        let t0 = Transcript::new(b"VRF");
        let io21 = keypair2.secret.vrf_create_from_compressed_point(out1).unwrap();
        let proofs21 = keypair2.dleq_proove(t0.clone(), &io21);
        let io12 = keypair1.secret.vrf_create_from_compressed_point(out2).unwrap();
        let proofs12 = keypair1.dleq_proove(t0.clone(), &io12);
        assert_eq!(io12.output, io21.output, "Sequential two-party VRF failed");
        assert_eq!(
            proofs21.0,
            proofs21.1.shorten_dleq(t0.clone(), &keypair2.public, &io21),
            "Oops `shorten_dleq` failed"
        );
        assert_eq!(
            proofs12.0,
            proofs12.1.shorten_dleq(t0.clone(), &keypair1.public, &io12),
            "Oops `shorten_dleq` failed"
        );
        assert!(keypair1
            .public
            .dleq_verify(t0.clone(), &io12, &proofs12.0)
            .is_ok());
        assert!(keypair2
            .public
            .dleq_verify(t0.clone(), &io21, &proofs21.0)
            .is_ok());
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn vrfs_merged_and_batched() {
        let keypairs: Vec<Keypair> = (0..4)
            .map(|_| Keypair::generate(&mut thread_rng()))
            .collect();

        let ctx = signing_context(b"yo!");
        let messages: [&[u8; 4]; 2] = [b"meow", b"woof"];
        let ts = || messages.iter().map(|m| ctx.bytes(*m));

        let ios_n_proofs = keypairs.iter().map(|k| k.vrfs_sign(ts())).collect::<Vec<(
            Box<[VRFInOut]>,
            VRFProof,
            VRFProofBatchable,
        )>>();

        for (k, (ios, proof, proof_batchable)) in keypairs.iter().zip(&ios_n_proofs) {
            let outs = ios
                .iter()
                .map(|io| io.to_output())
                .collect::<Vec<VRFOutput>>();
            let (ios_too, proof_too) = k
                .public
                .vrfs_verify(ts(), &outs, &proof)
                .expect("Valid VRF output verification failed!");
            assert_eq!(
                ios_too, *ios,
                "Output differs between signing and verification!"
            );
            assert_eq!(
                proof_too, *proof_batchable,
                "Returning batchable proof failed!"
            );
        }
        for (k, (ios, proof, _proof_batchable)) in keypairs.iter().zip(&ios_n_proofs) {
            let outs = ios.iter()
                .rev()
                .map(|io| io.to_output())
                .collect::<Vec<VRFOutput>>();
            assert!(
                k.public.vrfs_verify(ts(), &outs, &proof).is_err(),
                "Incorrect VRF output verification passed!"
            );
        }
        for (k, (ios, proof, _proof_batchable)) in keypairs.iter().rev().zip(&ios_n_proofs) {
            let outs = ios.iter()
                .map(|io| io.to_output())
                .collect::<Vec<VRFOutput>>();
            assert!(
                k.public.vrfs_verify(ts(), &outs, &proof).is_err(),
                "VRF output verification by a different signer passed!"
            );
        }

        let mut ios = keypairs.iter().enumerate()
            .map(|(i, keypair)| keypair.public.vrfs_merge_vartime(&ios_n_proofs[i].0))
            .collect::<Vec<VRFInOut>>();

        let mut proofs = ios_n_proofs.iter()
            .map(|(_ios, _proof, proof_batchable)| proof_batchable.clone())
            .collect::<Vec<VRFProofBatchable>>();

        let mut public_keys = keypairs.iter()
            .map(|keypair| keypair.public.clone())
            .collect::<Vec<PublicKey>>();

        assert!(
            dleq_verify_batch(&ios, &proofs, &public_keys).is_ok(),
            "Batch verification failed!"
        );
        proofs.reverse();
        assert!(
            dleq_verify_batch(&ios, &proofs, &public_keys).is_err(),
            "Batch verification with incorrect proofs passed!"
        );
        proofs.reverse();
        public_keys.reverse();
        assert!(
            dleq_verify_batch(&ios, &proofs, &public_keys).is_err(),
            "Batch verification with incorrect public keys passed!"
        );
        public_keys.reverse();
        ios.reverse();
        assert!(
            dleq_verify_batch(&ios, &proofs, &public_keys).is_err(),
            "Batch verification with incorrect points passed!"
        );
    }
}
