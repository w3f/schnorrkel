//! Implementation of the FROST protocol (<https://eprint.iacr.org/2020/852>).

#![allow(non_snake_case)]

/// FROST round 1 functionality and types.
pub mod round1 {
    #[cfg(feature = "cheater-detection")]
    use crate::olaf::frost::BindingFactor;
    use crate::{
        context::SigningTranscript,
        olaf::{identifier::Identifier, keys::SigningShare},
    };
    use alloc::vec::Vec;
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
    use derive_getters::Getters;
    use merlin::Transcript;
    use rand_core::{CryptoRng, RngCore};
    use std::{collections::BTreeMap, fmt::Debug};
    use zeroize::ZeroizeOnDrop;

    /// A scalar that is a signing nonce.
    #[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Nonce(pub(crate) Scalar);

    impl Nonce {
        /// Generates a new uniformly random signing nonce by sourcing fresh randomness and combining
        /// with the secret signing share, to hedge against a bad RNG.
        ///
        /// Each participant generates signing nonces before performing a signing
        /// operation.
        ///
        /// An implementation of `nonce_generate(secret)` from the [spec].
        ///
        /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-nonce-generation
        pub fn new<R>(secret: &SigningShare, rng: &mut R) -> Self
        where
            R: CryptoRng + RngCore,
        {
            let mut random_bytes = [0; 32];
            rng.fill_bytes(&mut random_bytes[..]);

            Self::nonce_generate_from_random_bytes(secret, &random_bytes[..])
        }

        /// Generates a nonce from the given random bytes.
        /// This function allows testing and MUST NOT be made public.
        pub(crate) fn nonce_generate_from_random_bytes(
            secret: &SigningShare,
            random_bytes: &[u8],
        ) -> Self {
            let mut transcript = Transcript::new(b"nonce_generate_from_random_bytes");

            transcript.append_message(b"random bytes", random_bytes);
            transcript.append_message(b"secret", secret.0.as_bytes());

            Self(transcript.challenge_scalar(b"nonce"))
        }
    }

    /// A group element that is a commitment to a signing nonce share.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct NonceCommitment(pub(super) RistrettoPoint);

    impl From<Nonce> for NonceCommitment {
        fn from(nonce: Nonce) -> Self {
            From::from(&nonce)
        }
    }

    impl From<&Nonce> for NonceCommitment {
        fn from(nonce: &Nonce) -> Self {
            Self(RISTRETTO_BASEPOINT_POINT * nonce.0)
        }
    }

    /// Comprised of hiding and binding nonces.
    ///
    /// Note that [`SigningNonces`] must be used *only once* for a signing
    /// operation; re-using nonces will result in leakage of a signer's long-lived
    /// signing key.
    #[derive(Debug, Clone, PartialEq, Eq, Getters, ZeroizeOnDrop)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SigningNonces {
        /// The hiding [`Nonce`].
        pub(crate) hiding: Nonce,
        /// The binding [`Nonce`].
        pub(crate) binding: Nonce,
        /// The commitments to the nonces. This is precomputed to improve
        /// sign() performance, since it needs to check if the commitments
        /// to the participant's nonces are included in the commitments sent
        /// by the Coordinator, and this prevents having to recompute them.
        #[zeroize(skip)]
        pub(crate) commitments: SigningCommitments,
    }

    impl SigningNonces {
        /// Generates a new signing nonce.
        ///
        /// Each participant generates signing nonces before performing a signing
        /// operation.
        pub fn new<R>(secret: &SigningShare, rng: &mut R) -> Self
        where
            R: CryptoRng + RngCore,
        {
            let hiding = Nonce::new(secret, rng);
            let binding = Nonce::new(secret, rng);

            Self::from_nonces(hiding, binding)
        }

        /// Generates a new [`SigningNonces`] from a pair of [`Nonce`].
        ///
        /// # Security
        ///
        /// SigningNonces MUST NOT be repeated in different FROST signings.
        /// Thus, if you're using this method (because e.g. you're writing it
        /// to disk between rounds), be careful so that does not happen.
        pub fn from_nonces(hiding: Nonce, binding: Nonce) -> Self {
            let hiding_commitment = (&hiding).into();
            let binding_commitment = (&binding).into();
            let commitments = SigningCommitments::new(hiding_commitment, binding_commitment);

            Self { hiding, binding, commitments }
        }
    }

    /// Published by each participant in the first round of the signing protocol.
    ///
    /// This step can be batched if desired by the implementation. Each
    /// SigningCommitment can be used for exactly *one* signature.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Getters)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SigningCommitments {
        /// Commitment to the hiding [`Nonce`].
        pub(crate) hiding: NonceCommitment,
        /// Commitment to the binding [`Nonce`].
        pub(crate) binding: NonceCommitment,
    }

    impl SigningCommitments {
        /// Create new SigningCommitments
        pub fn new(hiding: NonceCommitment, binding: NonceCommitment) -> Self {
            Self { hiding, binding }
        }

        /// Computes the [signature commitment share] from these round one signing commitments.
        ///
        /// [signature commitment share]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-signature-share-verificatio
        #[cfg(feature = "cheater-detection")]
        pub(super) fn to_group_commitment_share(
            self,
            binding_factor: &BindingFactor,
        ) -> GroupCommitmentShare {
            GroupCommitmentShare(self.hiding.0 + (self.binding.0 * binding_factor.0))
        }
    }

    impl From<&SigningNonces> for SigningCommitments {
        fn from(nonces: &SigningNonces) -> Self {
            nonces.commitments
        }
    }

    /// One signer's share of the group commitment, derived from their individual signing commitments
    /// and the binding factor _rho_.
    #[derive(Clone, Copy, PartialEq)]
    pub struct GroupCommitmentShare(pub(super) RistrettoPoint);

    /// Encode the list of group signing commitments.
    ///
    /// Implements [`encode_group_commitment_list()`] from the spec.
    ///
    /// `signing_commitments` must contain the sorted map of participants
    /// identifiers to the signing commitments they issued.
    ///
    /// Returns a byte string containing the serialized representation of the
    /// commitment list.
    ///
    /// [`encode_group_commitment_list()`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-list-operations
    pub(crate) fn encode_group_commitments(
        signing_commitments: &BTreeMap<Identifier, SigningCommitments>,
    ) -> Transcript {
        //let mut bytes = vec![];
        let mut transcript = Transcript::new(b"encode_group_commitments");

        for (item_identifier, item) in signing_commitments {
            transcript.append_message(b"identifier", item_identifier.0.as_bytes());
            transcript.commit_point(b"hiding", &item.hiding().0.compress());
            transcript.commit_point(b"binding", &item.binding().0.compress());
        }

        transcript
    }

    /// Done once by each participant, to generate _their_ nonces and commitments
    /// that are then used during signing.
    ///
    /// This is only needed if pre-processing is needed (for 1-round FROST). For
    /// regular 2-round FROST, use [`commit`].
    ///
    /// When performing signing using two rounds, num_nonces would equal 1, to
    /// perform the first round. Batching entails generating more than one
    /// nonce/commitment pair at a time.  Nonces should be stored in secret storage
    /// for later use, whereas the commitments are published.
    pub fn preprocess<R>(
        num_nonces: u8,
        secret: &SigningShare,
        rng: &mut R,
    ) -> (Vec<SigningNonces>, Vec<SigningCommitments>)
    where
        R: CryptoRng + RngCore,
    {
        let mut signing_nonces: Vec<SigningNonces> = Vec::with_capacity(num_nonces as usize);
        let mut signing_commitments: Vec<SigningCommitments> =
            Vec::with_capacity(num_nonces as usize);

        for _ in 0..num_nonces {
            let nonces = SigningNonces::new(secret, rng);
            signing_commitments.push(SigningCommitments::from(&nonces));
            signing_nonces.push(nonces);
        }

        (signing_nonces, signing_commitments)
    }

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Implements [`commit`] from the spec.
    ///
    /// Generates the signing nonces and commitments to be used in the signing
    /// operation.
    ///
    /// [`commit`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-round-one-commitment.
    pub fn commit<R>(secret: &SigningShare, rng: &mut R) -> (SigningNonces, SigningCommitments)
    where
        R: CryptoRng + RngCore,
    {
        let (mut vec_signing_nonces, mut vec_signing_commitments) = preprocess(1, secret, rng);
        (
            vec_signing_nonces.pop().expect("must have 1 element"),
            vec_signing_commitments.pop().expect("must have 1 element"),
        )
    }
}

/// FROST round 2 functionality and types.
pub mod round2 {
    use super::round1::{encode_group_commitments, SigningCommitments, SigningNonces};
    use crate::{
        context::{SigningContext, SigningTranscript},
        olaf::{
            errors::FROSTError,
            identifier::Identifier,
            keys::{KeyPackage, VerifyingKey},
        },
    };
    use alloc::{
        collections::{BTreeMap, BTreeSet},
        vec::Vec,
    };
    use curve25519_dalek::{
        traits::{Identity, VartimeMultiscalarMul},
        RistrettoPoint, Scalar,
    };
    use derive_getters::Getters;
    use merlin::Transcript;
    use std::fmt::Debug;

    pub(crate) type Challenge = Scalar;

    /// Generates the challenge as is required for Schnorr signatures.
    pub(crate) fn challenge(
        R: &RistrettoPoint,
        verifying_key: &VerifyingKey,
        context: &[u8],
        msg: &[u8],
    ) -> Challenge {
        let mut transcript = SigningContext::new(context).bytes(msg);

        transcript.proto_name(b"Schnorr-sig");
        transcript.commit_point(b"sign:pk", verifying_key.as_compressed());
        transcript.commit_point(b"sign:R", &R.compress());
        transcript.challenge_scalar(b"sign:c")
    }

    /// The binding factor, also known as _rho_ (ρ), ensures each signature share is strongly bound to a signing set, specific set
    /// of commitments, and a specific message.
    #[derive(Clone, PartialEq, Eq)]
    pub(crate) struct BindingFactor(pub(crate) Scalar);

    /// A list of binding factors and their associated identifiers.
    #[derive(Clone)]
    pub(crate) struct BindingFactorList(BTreeMap<Identifier, BindingFactor>);

    impl BindingFactorList {
        /// Create a new [`BindingFactorList`] from a map of identifiers to binding factors.
        pub fn new(binding_factors: BTreeMap<Identifier, BindingFactor>) -> Self {
            Self(binding_factors)
        }

        /// Get the [`BindingFactor`] for the given identifier, or None if not found.
        pub fn get(&self, key: &Identifier) -> Option<&BindingFactor> {
            self.0.get(key)
        }

        /// [`compute_binding_factors`] in the spec
        ///
        /// [`compute_binding_factors`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-4.4.
        pub(crate) fn compute_binding_factor_list(
            signing_package: &SigningPackage,
            verifying_key: &VerifyingKey,
        ) -> BindingFactorList {
            let mut transcripts = signing_package.binding_factor_transcripts(verifying_key);

            BindingFactorList::new(
                transcripts
                    .iter_mut()
                    .map(|(identifier, transcript)| {
                        let binding_factor = transcript.challenge_scalar(b"binding factor");

                        (*identifier, BindingFactor(binding_factor))
                    })
                    .collect(),
            )
        }
    }

    /// The product of all signers' individual commitments, published as part of the
    /// final signature.
    #[derive(Clone, PartialEq, Eq)]
    pub(crate) struct GroupCommitment(pub(crate) RistrettoPoint);

    /// Generates the group commitment which is published as part of the joint
    /// Schnorr signature.
    ///
    /// Implements [`compute_group_commitment`] from the spec.
    ///
    /// [`compute_group_commitment`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-4.5.
    pub(crate) fn compute_group_commitment(
        signing_package: &SigningPackage,
        binding_factor_list: &BindingFactorList,
    ) -> Result<GroupCommitment, FROSTError> {
        let identity = RistrettoPoint::identity();

        let mut group_commitment = RistrettoPoint::identity();

        // Number of signing participants we are iterating over.
        let signers = signing_package.signing_commitments().len();

        let mut binding_scalars = Vec::with_capacity(signers);

        let mut binding_elements = Vec::with_capacity(signers);

        for (commitment_identifier, commitment) in signing_package.signing_commitments() {
            // The following check prevents a party from accidentally revealing their share.
            // Note that the '&&' operator would be sufficient.
            if identity == commitment.binding.0 || identity == commitment.hiding.0 {
                return Err(FROSTError::IdentitySigningCommitment);
            }

            let binding_factor = binding_factor_list
                .get(commitment_identifier)
                .ok_or(FROSTError::UnknownIdentifier)?;

            // Collect the binding commitments and their binding factors for one big
            // multiscalar multiplication at the end.
            binding_elements.push(commitment.binding.0);
            binding_scalars.push(binding_factor.0);

            group_commitment += commitment.hiding.0;
        }

        let accumulated_binding_commitment: RistrettoPoint =
            RistrettoPoint::vartime_multiscalar_mul(binding_scalars, binding_elements);

        group_commitment += accumulated_binding_commitment;

        Ok(GroupCommitment(group_commitment))
    }

    /// A participant's signature share, which the coordinator will aggregate with all other signer's
    /// shares into the joint signature.
    #[derive(Debug, Clone, Copy, Eq, PartialEq, Getters)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SignatureShare {
        /// This participant's signature over the message.
        pub(crate) share: Scalar,
    }

    impl SignatureShare {
        /// Tests if a signature share issued by a participant is valid before
        /// aggregating it into a final joint signature to publish.
        ///
        /// This is the final step of [`verify_signature_share`] from the spec.
        ///
        /// [`verify_signature_share`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-signature-share-verificatio
        #[cfg(feature = "cheater-detection")]
        pub(crate) fn verify(
            &self,
            identifier: Identifier,
            group_commitment_share: &round1::GroupCommitmentShare,
            verifying_share: &VerifyingShare,
            lambda_i: Scalar,
            challenge: &Challenge,
        ) -> Result<(), FROSTError> {
            if (GENERATOR * self.share)
                != (group_commitment_share.0 + (verifying_share * challenge * lambda_i))
            {
                return Err(FROSTError::InvalidSignatureShare { culprit: identifier });
            }

            Ok(())
        }
    }

    /// Compute the signature share for a signing operation.
    pub(crate) fn compute_signature_share(
        signer_nonces: &SigningNonces,
        binding_factor: BindingFactor,
        lambda_i: Scalar,
        key_package: &KeyPackage,
        challenge: Challenge,
    ) -> SignatureShare {
        let z_share: Scalar = signer_nonces.hiding.0
            + (signer_nonces.binding.0 * binding_factor.0)
            + (lambda_i * key_package.signing_share.0 * challenge);

        SignatureShare { share: z_share }
    }

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Implements [`sign`] from the spec.
    ///
    /// Receives the message to be signed and a set of signing commitments and a set
    /// of randomizing commitments to be used in that signing operation, including
    /// that for this participant.
    ///
    /// Assumes the participant has already determined which nonce corresponds with
    /// the commitment that was assigned by the coordinator in the SigningPackage.
    ///
    /// [`sign`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-round-two-signature-share-g
    pub fn sign(
        signing_package: &SigningPackage,
        signer_nonces: &SigningNonces,
        key_package: &KeyPackage,
    ) -> Result<SignatureShare, FROSTError> {
        if signing_package.signing_commitments().len() < key_package.min_signers as usize {
            return Err(FROSTError::IncorrectNumberOfSigningCommitments);
        }

        // Validate the signer's commitment is present in the signing package
        let commitment = signing_package
            .signing_commitments
            .get(&key_package.identifier)
            .ok_or(FROSTError::MissingSigningCommitment)?;

        // Validate if the signer's commitment exists
        if &signer_nonces.commitments != commitment {
            return Err(FROSTError::IncorrectSigningCommitment);
        }

        // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
        // binding factor.
        let binding_factor_list: BindingFactorList = BindingFactorList::compute_binding_factor_list(
            signing_package,
            &key_package.verifying_key,
        );

        let binding_factor: BindingFactor = binding_factor_list
            .get(&key_package.identifier)
            .ok_or(FROSTError::UnknownIdentifier)?
            .clone();

        // Compute the group commitment from signing commitments produced in round one.
        let group_commitment = compute_group_commitment(signing_package, &binding_factor_list)?;

        // Compute Lagrange coefficient.
        let lambda_i = derive_interpolating_value(key_package.identifier(), signing_package)?;

        // Compute the per-message challenge.
        let challenge = challenge(
            &group_commitment.0,
            &key_package.verifying_key,
            signing_package.context.as_slice(),
            signing_package.message.as_slice(),
        );

        // Compute the Schnorr signature share.
        let signature_share = compute_signature_share(
            signer_nonces,
            binding_factor,
            lambda_i,
            key_package,
            challenge,
        );

        Ok(signature_share)
    }

    /// Generated by the coordinator of the signing operation and distributed to
    /// each signing party.
    #[derive(Clone, Debug, PartialEq, Eq, Getters)]
    pub struct SigningPackage {
        /// The set of commitments participants published in the first round of the
        /// protocol.
        signing_commitments: BTreeMap<Identifier, SigningCommitments>,
        /// Message which each participant will sign.
        ///
        /// Each signer should perform protocol-specific verification on the
        /// message.
        message: Vec<u8>,
        context: Vec<u8>,
    }

    impl SigningPackage {
        /// Create a new `SigningPackage`.
        ///
        /// The `signing_commitments` are sorted by participant `identifier`.
        pub fn new(
            signing_commitments: BTreeMap<Identifier, SigningCommitments>,
            message: &[u8],
            context: &[u8],
        ) -> SigningPackage {
            SigningPackage {
                signing_commitments,
                message: message.to_vec(),
                context: context.to_vec(),
            }
        }

        /// Get a signing commitment by its participant identifier, or None if not found.
        pub fn signing_commitment(&self, identifier: &Identifier) -> Option<SigningCommitments> {
            self.signing_commitments.get(identifier).copied()
        }

        /// Compute the transcripts to compute the per-signer binding factors.
        pub fn binding_factor_transcripts(
            &self,
            verifying_key: &VerifyingKey,
        ) -> Vec<(Identifier, Transcript)> {
            let mut transcript = Transcript::new(b"binding_factor");

            transcript.commit_point(b"verifying_key", verifying_key.as_compressed());

            transcript.append_message(b"message", self.message());

            transcript.append_message(
                b"group_commitment",
                encode_group_commitments(self.signing_commitments())
                    .challenge_scalar(b"encode_group_commitments")
                    .as_bytes(),
            );

            self.signing_commitments()
                .keys()
                .map(|identifier| {
                    transcript.append_message(b"identifier", identifier.0.as_bytes());
                    (*identifier, transcript.clone())
                })
                .collect()
        }
    }

    /// Generates the lagrange coefficient for the i'th participant (for `signer_id`).
    ///
    /// Implements [`derive_interpolating_value()`] from the spec.
    ///
    /// [`derive_interpolating_value()`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-polynomials
    pub(crate) fn derive_interpolating_value(
        signer_id: &Identifier,
        signing_package: &SigningPackage,
    ) -> Result<Scalar, FROSTError> {
        compute_lagrange_coefficient(
            &signing_package.signing_commitments().keys().cloned().collect(),
            None,
            *signer_id,
        )
    }

    /// Generates a lagrange coefficient.
    ///
    /// The Lagrange polynomial for a set of points (x_j, y_j) for 0 <= j <= k
    /// is ∑_{i=0}^k y_i.ℓ_i(x), where ℓ_i(x) is the Lagrange basis polynomial:
    ///
    /// ℓ_i(x) = ∏_{0≤j≤k; j≠i} (x - x_j) / (x_i - x_j).
    ///
    /// This computes ℓ_j(x) for the set of points `xs` and for the j corresponding
    /// to the given xj.
    ///
    /// If `x` is None, it uses 0 for it (since Identifiers can't be 0).
    fn compute_lagrange_coefficient(
        x_set: &BTreeSet<Identifier>,
        x: Option<Identifier>,
        x_i: Identifier,
    ) -> Result<Scalar, FROSTError> {
        if x_set.is_empty() {
            return Err(FROSTError::IncorrectNumberOfIdentifiers);
        }
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;

        let mut x_i_found = false;

        for x_j in x_set.iter() {
            if x_i == *x_j {
                x_i_found = true;
                continue;
            }

            if let Some(x) = x {
                num *= x.0 - x_j.0;
                den *= x_i.0 - x_j.0;
            } else {
                // Both signs inverted just to avoid requiring Neg (-*xj)
                num *= x_j.0;
                den *= x_j.0 - x_i.0;
            }
        }
        if !x_i_found {
            return Err(FROSTError::UnknownIdentifier);
        }

        let inverse = num * den.invert();

        if inverse == Scalar::ZERO {
            Err(FROSTError::DuplicatedIdentifier)
        } else {
            Ok(inverse)
        }
    }
}

/// FROST round 3 functionality and types, which corresponds to the aggregation of the signature shares of the round 2.
pub mod round3 {
    use crate::{
        olaf::{
            errors::FROSTError,
            identifier::Identifier,
            keys::{PublicKeyPackage, VerifyingKey},
        },
        Signature,
    };
    use alloc::collections::BTreeMap;
    use curve25519_dalek::Scalar;

    use super::round2::{compute_group_commitment, BindingFactorList, SignatureShare, SigningPackage};

    /// Aggregates the signature shares to produce a final signature that
    /// can be verified with the group public key.
    ///
    /// `signature_shares` maps the identifier of each participant to the
    /// [`round2::SignatureShare`] they sent. These identifiers must come from whatever mapping
    /// the coordinator has between communication channels and participants, i.e.
    /// they must have assurance that the [`round2::SignatureShare`] came from
    /// the participant with that identifier.
    ///
    /// This operation is performed by a coordinator that can communicate with all
    /// the signing participants before publishing the final signature. The
    /// coordinator can be one of the participants or a semi-trusted third party
    /// (who is trusted to not perform denial of service attacks, but does not learn
    /// any secret information). Note that because the coordinator is trusted to
    /// report misbehaving parties in order to avoid publishing an invalid
    /// signature, if the coordinator themselves is a signer and misbehaves, they
    /// can avoid that step. However, at worst, this results in a denial of
    /// service attack due to publishing an invalid signature.
    pub fn aggregate(
        signing_package: &SigningPackage,
        signature_shares: &BTreeMap<Identifier, SignatureShare>,
        pubkeys: &PublicKeyPackage,
    ) -> Result<Signature, FROSTError> {
        // Check if signing_package.signing_commitments and signature_shares have
        // the same set of identifiers, and if they are all in pubkeys.verifying_shares.
        if signing_package.signing_commitments().len() != signature_shares.len() {
            return Err(FROSTError::UnknownIdentifier);
        }

        if !signing_package.signing_commitments().keys().all(|id| {
            #[cfg(feature = "cheater-detection")]
            return signature_shares.contains_key(id)
                && pubkeys.verifying_shares().contains_key(id);
            #[cfg(not(feature = "cheater-detection"))]
            return signature_shares.contains_key(id);
        }) {
            return Err(FROSTError::UnknownIdentifier);
        }

        // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
        // binding factor.
        let binding_factor_list: BindingFactorList =
            BindingFactorList::compute_binding_factor_list(signing_package, &pubkeys.verifying_key);

        // Compute the group commitment from signing commitments produced in round one.
        let group_commitment = compute_group_commitment(signing_package, &binding_factor_list)?;

        // The aggregation of the signature shares by summing them up, resulting in
        // a plain Schnorr signature.
        //
        // Implements [`aggregate`] from the spec.
        //
        // [`aggregate`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-5.3
        let mut s = Scalar::ZERO;

        for signature_share in signature_shares.values() {
            s += signature_share.share;
        }

        let signature = Signature { R: group_commitment.0.compress(), s };

        // Verify the aggregate signature
        let verification_result = verify_signature(
            &signing_package.context(),
            &signing_package.message(),
            &signature,
            pubkeys.verifying_key(),
        );

        // Only if the verification of the aggregate signature failed; verify each share to find the cheater.
        // This approach is more efficient since we don't need to verify all shares
        // if the aggregate signature is valid (which should be the common case).
        #[cfg(feature = "cheater-detection")]
        if let Err(err) = verification_result {
            // Compute the per-message challenge.
            let challenge = challenge(
                &group_commitment.0,
                pubkeys.verifying_key(),
                signing_package.message().as_slice(),
            );

            // Verify the signature shares.
            for (signature_share_identifier, signature_share) in signature_shares {
                // Look up the public key for this signer, where `signer_pubkey` = _G.ScalarBaseMult(s[i])_,
                // and where s[i] is a secret share of the constant term of _f_, the secret polynomial.
                let signer_pubkey = pubkeys
                    .verifying_shares
                    .get(signature_share_identifier)
                    .ok_or(FROSTError::UnknownIdentifier)?;

                // Compute Lagrange coefficient.
                let lambda_i =
                    derive_interpolating_value(signature_share_identifier, signing_package)?;

                let binding_factor = binding_factor_list
                    .get(signature_share_identifier)
                    .ok_or(FROSTError::UnknownIdentifier)?;

                // Compute the commitment share.
                let R_share = signing_package
                    .signing_commitment(signature_share_identifier)
                    .ok_or(FROSTError::UnknownIdentifier)?
                    .to_group_commitment_share(binding_factor);

                // Compute relation values to verify this signature share.
                signature_share.verify(
                    *signature_share_identifier,
                    &R_share,
                    signer_pubkey,
                    lambda_i,
                    &challenge,
                )?;
            }

            // We should never reach here; but we return the verification error to be safe.
            return Err(err);
        }

        #[cfg(not(feature = "cheater-detection"))]
        verification_result?;

        Ok(signature)
    }

    /// Verify a purported `signature` with a pre-hashed [`Challenge`] made by the group public key.
    pub(crate) fn verify_signature(
        context: &[u8],
        msg: &[u8],
        signature: &crate::Signature,
        public_key: &VerifyingKey,
    ) -> Result<(), FROSTError> {
        public_key
            .verify_simple(context, msg, signature)
            .map_err(FROSTError::InvalidSignature)?;

        Ok(())
    }
}
