// -*- mode: rust; -*-
//
// This file is part of schnorr-dalek.
// Copyright (c) 2017-2018 Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - jeffrey Burdges <jeff@web3.foundation>

//! Dangerously malleable Schnorr signatures
//!
//! We provide this module only to acknoledge scope, but recommend
//! strongly against its use, and do not provide tests or use the
//! module, even behind a feature gate.

use curve25519_dalek::digest::{Input};  // ExtendableOutput,XofReader
use curve25519_dalek::digest::generic_array::typenum::U64;

use super::*;


https://crypto.stackexchange.com/questions/60825/schnorr-pubkey-recovery
https://www.deadalnix.me/2017/02/17/schnorr-signatures-for-not-so-dummies/

impl Signature {
    /// Extract the public signing key from a dangerously malleable Schnorr signatures
    ///
    /// There is deprecated style of Schnorr signatures in which the 
    /// public key does not make an apperance in the signature's onw
    /// derivation of `k`, but may optionally influence k by appearing
    /// in the message body.  We cnanot use these more malleable
    /// signatures for standard blockchain applications, like accounts,
    /// becuase they break many advanced features, like ["hierarchical
    /// deterministic" key derivation.](https://www.deadalnix.me/2017/02/17/schnorr-signatures-for-not-so-dummies/)
    ///
    /// There are however applications that never require such features
    /// but benefint form smaller signatures, in which case this
    /// function can extract the public signing key from a signature
    /// We recommend strongly against doing this.
    // https://crypto.stackexchange.com/questions/60825/schnorr-pubkey-recovery
    pub signer_from_dangerously_malleable(&self) -> Result<PublicKey,SignatureError> {
        let k_inv = scalars::scalar_from_xof(
            context.context_digest()
            .chain(signature.R.as_bytes())
            // .chain(public_key.compressed.as_bytes())  // DANGER !!!
            .chain(&message)
        ).invert();
        let mut point = &self.s * &constants::RISTRETTO_BASEPOINT_TABLE;
        point -= signature.R.decompress() ?;
        point *= &k_inv;
        PublicKey {
            compressed: point.compress(),
            point
        }
    }
}

impl SecretKey {
    /// Dangerously malleably sign a message with this `SecretKey`.
    ///
    /// There is deprecated style of Schnorr signatures in which the 
    /// public key does not make an apperance in the signature's onw
    /// derivation of `k`, but may optionally influence k by appearing
    /// in the message body.  We cnanot use these more malleable
    /// signatures for standard blockchain applications, like accounts,
    /// becuase they break many advanced features, like ["hierarchical
    /// deterministic" key derivation.](https://www.deadalnix.me/2017/02/17/schnorr-signatures-for-not-so-dummies/)
    ///
    /// There are however applications that never require such features
    /// but benefint form smaller signatures, in which case this
    /// function can extract the public signing key from a signature
    /// We recommend strongly against doing this.
    #[allow(non_snake_case)]
    pub fn sign_dangerously_malleable<C>(&self, context: &C, message: &[u8]) -> Signature
    where C: SigningContext,
          C::Digest: ExtendableOutput
    {
        let R: CompressedRistretto;
        let r: Scalar;
        let s: Scalar;
        let k: Scalar;

        r = scalars::scalar_from_xof(
            context.nonce_randomness()
            .chain(&self.nonce)
            .chain(&message)
        );
        R = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();

        k = scalars::scalar_from_xof(
            context.context_digest()
            .chain(R.as_bytes())
            // .chain(public_key.compressed.as_bytes())  // DANGER !!!
            .chain(&message)
        );
        s = &(&k * &self.key) + &r;

        Signature{ R, s }
    }
}

impl PublicKey {
    /// Verify a dangerously malleable signature on a message with this public key.
    ///
    /// These dangerously malleable signatures always verify when checked with
    /// the signature produced by `signer_from_dangerously_malleable` so
    /// perhaps only that funcituon should exist.
    #[allow(non_snake_case)]
    pub fn verify_dangerously_malleable<C>(&self, context: &C, message: &[u8], signature: &Signature) -> bool
    where C: SigningContext,
          C::Digest: ExtendableOutput
    {
        let A: RistrettoPoint = self.point;
        let R: RistrettoPoint;
        let k: Scalar;

        k = scalars::scalar_from_xof(
            context.context_digest()
            .chain(signature.R.as_bytes())
            // .chain(public_key.compressed.as_bytes())  // DANGER !!!
            .chain(&message)
        );
        R = RistrettoPoint::vartime_double_scalar_mul_basepoint(&k, &(-A), &signature.s);

        R.compress() == signature.R
    }
}

