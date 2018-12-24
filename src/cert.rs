// -*- mode: rust; -*-
//
// This file is part of schnorr-dalek.
// Copyright (c) 2017-2018 Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - jeffrey Burdges <jeff@web3.foundation>


//! Elliptic curve Qu-Vanstone implicit certificate scheme (ECQV) for Ristretto
//!
//! [Implicit certificates](https://en.wikipedia.org/wiki/Implicit_certificate)
//! provide an extremely space efficent public key certificate scheme.  
//!
//! As a rule, implicit certificates do not prove possession of the
//! private key.  We thus worry more about fear rogue key attack when
//! using them, but all protocols here should provide strong defenses
//! against then.
//!
//! [1] "Standards for efficient cryptography, SEC 4: Elliptic Curve
//!     Qu-Vanstone Implicit Certificate Scheme (ECQV)".
//!     http://www.secg.org/sec4-1.0.pdf
//! [2] Daniel R. L. Brown, Robert P. Gallant, and Scott A. Vanstone.
//!     "Provably Secure Implicit Certificate Schemes". Financial
//!     Cryptography 2001. Lecture Notes in Computer Science.
//!     Springer Berlin Heidelberg. 2339 (1): 156–165. doi:10.1007/3-540-46088-8_15.
//!     http://www.cacr.math.uwaterloo.ca/techreports/2000/corr2000-55.ps

use rand::prelude::*;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto};
use curve25519_dalek::scalar::Scalar;

use context::SigningTranscript;

use super::*;


/// ECQV Implicit Certificate Secret
///
/// Issuing an ECQV implicit certificate requires producing
/// this and securely sending it to the certificate holder.
#[derive(Clone, Copy)] // Debug, Eq, PartialEq
pub struct ECQVCertSecret(pub [u8; 64]);
/// TODO: Serde serialization/deserialization

/*
impl<'a> From<&'a ECQVCertSecret> for &'a ECQVCertPublic {
	from(secret: &ECQVCertSecret) -> &ECQVCertPublic {
        unsafe { ::std::mem::transmute(secret) }
    }
}
*/

impl From<ECQVCertSecret> for ECQVCertPublic {
	fn from(secret: ECQVCertSecret) -> ECQVCertPublic {
		let mut public = ECQVCertPublic([0u8; 32]);
		public.0.copy_from_slice(&secret.0[0..32]);
		public
	}
}

/// ECQV Implicit Certificate Public Key Reconstruction Data
///
/// Identifying the public key of, and implicity verifying, an ECQV
/// implicit certificate requires this data, which is produced
/// when the certificate holder accepts the implicit certificate.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ECQVCertPublic(pub [u8; 32]);
/// TODO: Serde serialization/deserialization

impl ECQVCertPublic {
	fn derive_e<T: SigningTranscript>(&self, mut t: T) -> Scalar {
		t.challenge_scalar(b"e")
	}
}

impl Keypair {
	/// Issue an ECQV implicit certificate
	///
	/// Aside from the issuing `Keypair` supplied as `self`, you provide both
	/// (1) a digest `h` that incorporates both the context and the
	///     certificate requester's identity, and 
	/// (2) the `seed_public_key` supplied by the certificate recipient
	///     in their certificate request.
	/// We return an `ECQVCertSecret` which the issuer sent to the
	/// certificate requester, ans from which the certificate requester
	/// derives their certified key pair.
	pub fn issue_ecqv_cert<T>(&self, mut t: T, seed_public_key: &PublicKey) -> ECQVCertSecret
	where T: SigningTranscript
	{
		t.proto_name(b"ECQV");
		t.commit_point(b"Issuer-pk",&self.public.compressed);

        // We cannot commit the `seed_public_key` to the transcript
		// because the whole point is to keep the transcript minimal.
		// Instead we consume it as witness datathat influences only k.
        let k = t.witness_scalar(&self.secret.nonce,Some(seed_public_key.compressed.as_bytes()));

        // Compute the public key reconstruction data
		let gamma = seed_public_key.point + &k * &constants::RISTRETTO_BASEPOINT_TABLE;
		let cert_public = ECQVCertPublic(gamma.compress().0);

        // Compute the secret key reconstruction data
		let s = cert_public.derive_e(t) * k + self.secret.key;

		let mut cert_secret = ECQVCertSecret([0u8; 64]);
		cert_secret.0[0..32].copy_from_slice(&cert_public.0[..]);
		cert_secret.0[32..64].copy_from_slice(s.as_bytes());
		cert_secret
	}
}

impl PublicKey {
	/// Accept an ECQV implicit certificate
	///
	/// We request an ECQV implicit certificate by first creating an
	/// ephemeral `Keypair` and sending the public portion to the issuer
	/// as `seed_public_key`.  An issuer issues the certificat by replying
	/// with the `ECQVCertSecret` created by `issue_ecqv_cert`.
    /// 
	/// Aside from the issuer `PublicKey` supplied as `self`, you provide
	/// (1) a digest `h` that incorporates both the context and the
	///     certificate requester's identity, 
	/// (2) the `seed_secret_key` corresponding to the `seed_public_key`
	///     they sent to the issuer by the certificate recipient in their
	///     certificate request, and
	/// (3) the `ECQVCertSecret` send by the issuer to the certificate
	///     requester.
	/// We return both your certificate's new `SecretKey` as well as
	/// an `ECQVCertPublic` from which third parties may derive
	/// corresponding public key from `h` and the issuer's public key.
	pub fn accept_ecqv_cert<T>(
		&self,
	    mut t: T,
		seed_secret_key: &SecretKey,
		cert_secret: ECQVCertSecret
	) -> Result<(ECQVCertPublic, SecretKey),SignatureError>
	where T: SigningTranscript
    {
		t.proto_name(b"ECQV");
		t.commit_point(b"Issuer-pk",&self.compressed);

        // Again we cannot commit much to the transcript, but we again 
		// treat anything relevant as a witness when defining the 
        let mut nonce = [0u8; 32];
        t.witness_bytes(&mut nonce, &cert_secret.0[..],Some(&seed_secret_key.nonce));

        let mut s = [0u8; 32];
        s.copy_from_slice(&cert_secret.0[32..64]);
        let s = Scalar::from_canonical_bytes(s).ok_or(SignatureError::ScalarFormatError) ?;
        let cert_public : ECQVCertPublic = cert_secret.into();
        let key = s + cert_public.derive_e(t) * seed_secret_key.key;
        Ok(( cert_public, SecretKey { key, nonce } ))
    }
}

impl Keypair {
    /// Issue an ECQV Implicit Certificate for yourself
	///
	/// We can issue an implicit certificate to ourselves if we merely
	/// want to certify an associated public key.  We should prefer
	/// this option over "hierarchical deterministic" key derivation
	/// because compromizing the resulting secret key does not 
	/// compromize the issuer's secret key.
	/// 
	/// In this case, we avoid the entire interactive protocol described 
	/// by `issue_ecqv_cert` and `accept_ecqv_cert` by hiding it an all
	/// managment of the ephemeral `Keypair` inside this function.
	///
	/// Aside from the issuing secret key supplied as `self`, you provide
	/// only a digest `h` that incorporates any context and metadata
	/// pertaining to the issued key.  
	pub fn issue_self_ecqv_cert<T>(&self, t: T) -> (ECQVCertPublic, SecretKey)
	where T: SigningTranscript+Clone
	{
	    let seed = Keypair::generate(thread_rng());
		let cert_secret = self.issue_ecqv_cert(t.clone(), &seed.public);
		self.public.accept_ecqv_cert(t, &seed.secret, cert_secret).unwrap()
	}
}

impl PublicKey {
	///
	pub fn open_ecqv_cert<T>(&self, mut t: T, cert_public: &ECQVCertPublic) -> Result<PublicKey,SignatureError>
	where T: SigningTranscript
	{
		t.proto_name(b"ECQV");
		t.commit_point(b"Issuer-pk",&self.compressed);

		let gamma = CompressedRistretto(cert_public.0.clone()).decompress()
		    .ok_or(SignatureError::PointDecompressionError) ?;

		let point = self.point + cert_public.derive_e(t) * gamma;
		Ok(PublicKey {
			compressed: point.compress(),
			point
		})
	}
}

#[cfg(test)]
mod tests {
    use rand::prelude::*;
    use sha3::{Shake128};

    use context::signing_context;
    use super::*;

    #[test]
    fn ecqv_cert_public_vs_private_paths() {
		let t = signing_context(b"").bytes(b"MrMeow!");
	    let issuer = Keypair::generate(thread_rng());
		let (cert_public,secret_key) = issuer.issue_self_ecqv_cert(t.clone());
		let public_key = issuer.public.open_ecqv_cert(t,&cert_public).unwrap();
		assert_eq!(secret_key.to_public(), public_key);
	}	
}

