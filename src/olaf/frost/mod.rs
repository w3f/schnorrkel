//! Implementation of the FROST protocol (<https://eprint.iacr.org/2020/852>).

#![allow(non_snake_case)]

mod types;
mod errors;

use alloc::vec::Vec;
use curve25519_dalek::Scalar;
use rand_core::{CryptoRng, RngCore};
use crate::{
    context::{SigningContext, SigningTranscript},
    Signature,
};
use self::{
    errors::{FROSTError, FROSTResult},
    types::{
        BindingFactor, BindingFactorList, GroupCommitment, SignatureShare, SigningCommitments,
        SigningNonces,
    },
};

use super::{
    simplpedpop::{DKGOutput, SecretPolynomial},
    GroupPublicKey, SigningKeypair, VerifyingShare,
};

impl SigningKeypair {
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
        &self,
        num_nonces: u8,
        rng: &mut R,
    ) -> (Vec<SigningNonces>, Vec<SigningCommitments>)
    where
        R: CryptoRng + RngCore,
    {
        let mut signing_nonces: Vec<SigningNonces> = Vec::with_capacity(num_nonces as usize);
        let mut signing_commitments: Vec<SigningCommitments> =
            Vec::with_capacity(num_nonces as usize);

        for _ in 0..num_nonces {
            let nonces = SigningNonces::new(&self.0.secret, rng);
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
    pub fn commit<R>(&self, rng: &mut R) -> (SigningNonces, SigningCommitments)
    where
        R: CryptoRng + RngCore,
    {
        let (mut vec_signing_nonces, mut vec_signing_commitments) = self.preprocess(1, rng);
        (
            vec_signing_nonces.pop().expect("must have 1 element"),
            vec_signing_commitments.pop().expect("must have 1 element"),
        )
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
        &self,
        context: &[u8],
        message: &[u8],
        dkg_output: &DKGOutput,
        all_signing_commitments: &[SigningCommitments],
        signer_nonces: &SigningNonces,
    ) -> FROSTResult<SignatureShare> {
        if dkg_output.verifying_keys.len() != dkg_output.parameters.participants as usize {
            return Err(FROSTError::IncorrectNumberOfVerifyingShares);
        }

        if !all_signing_commitments.contains(&signer_nonces.commitments) {
            return Err(FROSTError::MissingOwnSigningCommitment);
        }

        let mut identifiers = Vec::new();
        let mut shares = Vec::new();

        let mut index = 0;

        let own_verifying_share = VerifyingShare(self.0.public);

        for (i, (identifier, share)) in dkg_output.verifying_keys.iter().enumerate() {
            identifiers.push(identifier);
            shares.push(share);

            if share == &own_verifying_share {
                index = i;
            }
        }

        if !shares.contains(&&own_verifying_share) {
            return Err(FROSTError::InvalidOwnVerifyingShare);
        }

        if all_signing_commitments.len() < dkg_output.parameters.threshold as usize {
            return Err(FROSTError::InvalidNumberOfSigningCommitments);
        }

        let binding_factor_list: BindingFactorList = BindingFactorList::compute(
            all_signing_commitments,
            &dkg_output.group_public_key,
            message,
        );

        let group_commitment =
            GroupCommitment::compute(all_signing_commitments, &binding_factor_list)?;

        let identifiers_vec: Vec<_> = dkg_output.verifying_keys.iter().map(|x| x.0).collect();

        let lambda_i = SecretPolynomial::compute_lagrange_coefficient(
            &identifiers_vec,
            None,
            *identifiers[index],
        );

        let mut transcript = SigningContext::new(context).bytes(message);
        transcript.proto_name(b"Schnorr-sig");
        {
            let this = &mut transcript;
            let compressed = dkg_output.group_public_key.0.as_compressed();
            this.append_message(b"sign:pk", compressed.as_bytes());
        };
        transcript.commit_point(b"sign:R", &group_commitment.0.compress());
        let challenge = transcript.challenge_scalar(b"sign:c");

        let signature_share = self.compute_signature_share(
            signer_nonces,
            &binding_factor_list.0[index].1,
            &lambda_i,
            &challenge,
        );

        Ok(signature_share)
    }

    fn compute_signature_share(
        &self,
        signer_nonces: &SigningNonces,
        binding_factor: &BindingFactor,
        lambda_i: &Scalar,
        challenge: &Scalar,
    ) -> SignatureShare {
        let z_share: Scalar = signer_nonces.hiding.0
            + (signer_nonces.binding.0 * binding_factor.0)
            + (lambda_i * self.0.secret.key * challenge);

        SignatureShare { share: z_share }
    }
}

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
    message: &[u8],
    context: &[u8],
    signing_commitments: &[SigningCommitments],
    signature_shares: &Vec<SignatureShare>,
    group_public_key: GroupPublicKey,
) -> Result<Signature, FROSTError> {
    if signing_commitments.len() != signature_shares.len() {
        return Err(FROSTError::IncorrectNumberOfSigningCommitments);
    }

    let binding_factor_list: BindingFactorList =
        BindingFactorList::compute(signing_commitments, &group_public_key, message);

    let group_commitment = GroupCommitment::compute(signing_commitments, &binding_factor_list)?;

    let mut s = Scalar::ZERO;

    for signature_share in signature_shares {
        s += signature_share.share;
    }

    let signature = Signature { R: group_commitment.0.compress(), s };

    group_public_key
        .0
        .verify_simple(context, message, &signature)
        .map_err(FROSTError::InvalidSignature)?;

    Ok(signature)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use rand::Rng;
    use rand_core::OsRng;
    use crate::{
        olaf::{
            simplpedpop::{AllMessage, Parameters},
            MINIMUM_THRESHOLD,
        },
        Keypair, PublicKey,
    };
    use super::{
        aggregate,
        types::{SigningCommitments, SigningNonces},
    };

    const MAXIMUM_PARTICIPANTS: u16 = 2;
    const MINIMUM_PARTICIPANTS: u16 = 2;
    const NONCES: u8 = 10;

    fn generate_parameters() -> Parameters {
        let mut rng = rand::thread_rng();
        let participants = rng.gen_range(MINIMUM_PARTICIPANTS..=MAXIMUM_PARTICIPANTS);
        let threshold = rng.gen_range(MINIMUM_THRESHOLD..=participants);

        Parameters { participants, threshold }
    }

    #[test]
    fn test_n_of_n_frost_with_simplpedpop() {
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public).collect();

        let mut all_messages = Vec::new();
        for i in 0..participants {
            let message: AllMessage = keypairs[i]
                .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                .unwrap();
            all_messages.push(message);
        }

        let mut dkg_outputs = Vec::new();

        for kp in keypairs.iter() {
            let dkg_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();
            dkg_outputs.push(dkg_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for dkg_output in &dkg_outputs {
            let (signing_nonces, signing_commitments) = dkg_output.1.commit(&mut OsRng);
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let mut signature_shares = Vec::new();

        let message = b"message";
        let context = b"context";

        for (i, dkg_output) in dkg_outputs.iter().enumerate() {
            let signature_share = dkg_output
                .1
                .sign(
                    context,
                    message,
                    &dkg_output.0.dkg_output,
                    &all_signing_commitments,
                    &all_signing_nonces[i],
                )
                .unwrap();

            signature_shares.push(signature_share);
        }

        aggregate(
            message,
            context,
            &all_signing_commitments,
            &signature_shares,
            dkg_outputs[0].0.dkg_output.group_public_key,
        )
        .unwrap();
    }

    #[test]
    fn test_t_of_n_frost_with_simplpedpop() {
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public).collect();

        let mut all_messages = Vec::new();
        for i in 0..participants {
            let message: AllMessage = keypairs[i]
                .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                .unwrap();
            all_messages.push(message);
        }

        let mut dkg_outputs = Vec::new();

        for kp in keypairs.iter() {
            let dkg_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();
            dkg_outputs.push(dkg_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for dkg_output in &dkg_outputs[..threshold] {
            let (signing_nonces, signing_commitments) = dkg_output.1.commit(&mut OsRng);
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let mut signature_shares = Vec::new();

        let message = b"message";
        let context = b"context";

        for (i, dkg_output) in dkg_outputs[..threshold].iter().enumerate() {
            let signature_share = dkg_output
                .1
                .sign(
                    context,
                    message,
                    &dkg_output.0.dkg_output,
                    &all_signing_commitments,
                    &all_signing_nonces[i],
                )
                .unwrap();

            signature_shares.push(signature_share);
        }

        aggregate(
            message,
            context,
            &all_signing_commitments,
            &signature_shares,
            dkg_outputs[0].0.dkg_output.group_public_key,
        )
        .unwrap();
    }

    #[test]
    fn test_preprocessing_frost_with_simplpedpop() {
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public).collect();

        let mut all_messages = Vec::new();
        for i in 0..participants {
            let message: AllMessage = keypairs[i]
                .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                .unwrap();
            all_messages.push(message);
        }

        let mut dkg_outputs = Vec::new();

        for kp in &keypairs {
            let dkg_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();
            dkg_outputs.push(dkg_output);
        }

        let group_public_key = dkg_outputs[0].0.dkg_output.group_public_key;

        let mut all_nonces_map: Vec<Vec<SigningNonces>> = Vec::new();
        let mut all_commitments_map: Vec<Vec<SigningCommitments>> = Vec::new();

        for dkg_output in &dkg_outputs {
            let (nonces, commitments) = dkg_output.1.preprocess(NONCES, &mut OsRng);

            all_nonces_map.push(nonces);
            all_commitments_map.push(commitments);
        }

        let mut nonces: Vec<&SigningNonces> = Vec::new();
        let mut commitments: Vec<Vec<SigningCommitments>> = Vec::new();

        for i in 0..NONCES {
            let mut comms = Vec::new();

            for (j, _) in dkg_outputs.iter().enumerate() {
                nonces.push(&all_nonces_map[j][i as usize]);
                comms.push(all_commitments_map[j][i as usize].clone())
            }
            commitments.push(comms);
        }

        let mut signature_shares = Vec::new();

        let mut messages = Vec::new();

        for i in 0..NONCES {
            let mut message = b"message".to_vec();
            message.extend_from_slice(&i.to_be_bytes());
            messages.push(message);
        }

        let context = b"context";

        for i in 0..NONCES {
            let message = &messages[i as usize];

            let commitments: Vec<SigningCommitments> = commitments[i as usize].clone();

            for (j, dkg_output) in dkg_outputs.iter().enumerate() {
                let nonces_to_use = &all_nonces_map[j][i as usize];

                let signature_share = dkg_output
                    .1
                    .sign(context, &message, &dkg_output.0.dkg_output, &commitments, nonces_to_use)
                    .unwrap();

                signature_shares.push(signature_share);
            }

            aggregate(&message, context, &commitments, &signature_shares, group_public_key)
                .unwrap();

            signature_shares = Vec::new();
        }
    }
}
