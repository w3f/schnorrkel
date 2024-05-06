//! Implementation of the SimplPedPoP protocol (<https://eprint.iacr.org/2023/899>), a DKG based on PedPoP, which in turn is based
//! on Pedersen's DKG. All of them have as the fundamental building block the Shamir's Secret Sharing scheme.

use alloc::vec::Vec;
use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use merlin::Transcript;
use rand_core::RngCore;
use crate::{context::SigningTranscript, verify_batch, Keypair, PublicKey};
use super::{
    data_structures::{
        AllMessage, DKGOutput, DKGOutputContent, MessageContent, Parameters,
        ENCRYPTION_NONCE_LENGTH, RECIPIENTS_HASH_LENGTH,
    },
    errors::{DKGError, DKGResult},
    utils::{
        decrypt, derive_secret_key_from_secret, encrypt, evaluate_polynomial,
        evaluate_polynomial_commitment, generate_coefficients, generate_identifier,
        sum_commitments,
    },
    GENERATOR,
};

impl Keypair {
    /// First round of the SimplPedPoP protocol.
    pub fn simplpedpop_contribute_all(
        &self,
        threshold: u16,
        recipients: Vec<PublicKey>,
    ) -> DKGResult<AllMessage> {
        let parameters = Parameters::generate(recipients.len() as u16, threshold);
        parameters.validate()?;

        let mut rng = crate::getrandom_or_panic();

        // We do not recipients.sort() because the protocol is simpler
        // if we require that all contributions provide the list in
        // exactly the same order.
        //
        // Instead we create a kind of session id by hashing the list
        // provided, but we provide only hash to recipients, not the
        // full recipients list.
        let mut recipients_transcript = merlin::Transcript::new(b"RecipientsHash");
        parameters.commit(&mut recipients_transcript);
        for r in recipients.iter() {
            recipients_transcript.commit_point(b"recipient", r.as_compressed());
        }
        let mut recipients_hash = [0u8; RECIPIENTS_HASH_LENGTH];
        recipients_transcript.challenge_bytes(b"finalize", &mut recipients_hash);

        let coefficients = generate_coefficients(parameters.threshold as usize - 1, &mut rng);

        let scalar_evaluations: Vec<Scalar> = (0..parameters.participants)
            .map(|i| {
                let identifier = generate_identifier(&recipients_hash, i);
                evaluate_polynomial(&identifier, &coefficients)
            })
            .collect();

        let point_polynomial: Vec<RistrettoPoint> =
            coefficients.iter().map(|c| GENERATOR * *c).collect();

        let mut encryption_transcript = merlin::Transcript::new(b"Encryption");
        parameters.commit(&mut encryption_transcript);
        encryption_transcript.commit_point(b"contributor", self.public.as_compressed());

        let mut encryption_nonce = [0u8; ENCRYPTION_NONCE_LENGTH];
        rng.fill_bytes(&mut encryption_nonce);
        encryption_transcript.append_message(b"nonce", &encryption_nonce);

        let ephemeral_key = Keypair::generate();

        let ciphertexts: Vec<Vec<u8>> = (0..parameters.participants)
            .map(|i| {
                encrypt(
                    &scalar_evaluations[i as usize],
                    &ephemeral_key.secret.key,
                    encryption_transcript.clone(),
                    &recipients[i as usize],
                    &encryption_nonce,
                    i as usize,
                )
            })
            .collect::<DKGResult<Vec<Vec<u8>>>>()?;

        let pk = &PublicKey::from_point(
            *point_polynomial
                .first()
                .expect("This never fails because the minimum threshold is 2"),
        );

        let secret = coefficients
            .first()
            .expect("This never fails because the minimum threshold is 2");

        let secret_key = derive_secret_key_from_secret(secret, &mut rng);

        let secret_commitment = point_polynomial
            .first()
            .expect("This never fails because the minimum threshold is 2");

        let mut pop_transcript = Transcript::new(b"pop");
        pop_transcript
            .append_message(b"secret commitment", secret_commitment.compress().as_bytes());
        let proof_of_possession = secret_key.sign(pop_transcript, pk);

        let message_content = MessageContent::new(
            self.public,
            encryption_nonce,
            parameters,
            recipients_hash,
            point_polynomial,
            ciphertexts,
            ephemeral_key.public,
            proof_of_possession,
        );

        let mut signature_transcript = Transcript::new(b"signature");
        signature_transcript.append_message(b"message", &message_content.to_bytes());
        let signature = self.sign(signature_transcript);

        Ok(AllMessage::new(message_content, signature))
    }

    /// Second round of the SimplPedPoP protocol.
    pub fn simplpedpop_recipient_all(
        &self,
        messages: &[AllMessage],
    ) -> DKGResult<(DKGOutput, Scalar)> {
        let first_message = &messages[0];
        let parameters = &first_message.content.parameters;
        let threshold = parameters.threshold as usize;
        let participants = parameters.participants as usize;

        first_message.content.parameters.validate()?;

        if messages.len() < participants {
            return Err(DKGError::InvalidNumberOfMessages);
        }

        let mut secret_shares = Vec::with_capacity(participants);
        let mut verifying_keys = Vec::with_capacity(participants);
        let mut public_keys = Vec::with_capacity(participants);
        let mut proofs_of_possession = Vec::with_capacity(participants);
        let mut senders = Vec::with_capacity(participants);
        let mut signatures = Vec::with_capacity(participants);
        let mut signatures_transcripts = Vec::with_capacity(participants);
        let mut pops_transcripts = Vec::with_capacity(participants);
        let mut group_point = RistrettoPoint::identity();
        let mut total_secret_share = Scalar::ZERO;
        let mut total_polynomial_commitment = Vec::new();
        let mut identifiers = Vec::new();

        for (j, message) in messages.iter().enumerate() {
            if &message.content.parameters != parameters {
                return Err(DKGError::DifferentParameters);
            }
            if &message.content.recipients_hash != &first_message.content.recipients_hash {
                return Err(DKGError::DifferentRecipientsHash);
            }

            let content = &message.content;
            let point_polynomial = &content.point_polynomial;
            let ciphertexts = &content.ciphertexts;

            let public_key = PublicKey::from_point(
                *point_polynomial
                    .first()
                    .expect("This never fails because the minimum threshold is 2"),
            );
            public_keys.push(public_key);
            proofs_of_possession.push(content.proof_of_possession);

            senders.push(content.sender);
            signatures.push(message.signature);

            let mut encryption_transcript = merlin::Transcript::new(b"Encryption");
            parameters.commit(&mut encryption_transcript);
            encryption_transcript.commit_point(b"contributor", content.sender.as_compressed());
            encryption_transcript.append_message(b"nonce", &content.encryption_nonce);

            if point_polynomial.len() != threshold - 1 {
                return Err(DKGError::IncorrectNumberOfCommitments);
            }
            if ciphertexts.len() != participants {
                return Err(DKGError::IncorrectNumberOfEncryptedShares);
            }

            let mut signature_transcript = Transcript::new(b"signature");
            signature_transcript.append_message(b"message", &content.to_bytes());
            signatures_transcripts.push(signature_transcript);

            let mut pop_transcript = Transcript::new(b"pop");
            let secret_commitment = point_polynomial
                .first()
                .expect("This never fails because the minimum threshold is 2");
            pop_transcript
                .append_message(b"secret commitment", secret_commitment.compress().as_bytes());
            pops_transcripts.push(pop_transcript);

            if total_polynomial_commitment.is_empty() {
                total_polynomial_commitment = point_polynomial.clone();
            } else {
                total_polynomial_commitment =
                    sum_commitments(&[&total_polynomial_commitment, point_polynomial])?;
            }

            let key_exchange = self.secret.key * content.ephemeral_key.into_point();
            for (i, ciphertext) in ciphertexts.iter().enumerate() {
                if identifiers.len() != participants {
                    let identifier =
                        generate_identifier(&first_message.content.recipients_hash, i as u16);
                    identifiers.push(identifier);
                }

                if let Ok(secret_share) = decrypt(
                    encryption_transcript.clone(),
                    &self.public,
                    &key_exchange,
                    ciphertext,
                    &content.encryption_nonce,
                    i,
                ) {
                    if secret_share * GENERATOR
                        == evaluate_polynomial_commitment(&identifiers[i], point_polynomial)
                    {
                        secret_shares.push(secret_share);
                        break;
                    }
                }
            }

            total_secret_share += secret_shares.get(j).ok_or(DKGError::InvalidSecretShare)?;
            group_point += secret_commitment;
        }

        verify_batch(&mut pops_transcripts, &proofs_of_possession, &public_keys, false)
            .map_err(DKGError::InvalidProofOfPossession)?;

        verify_batch(&mut signatures_transcripts, &signatures, &senders, false)
            .map_err(DKGError::InvalidSignature)?;

        for i in 0..participants {
            verifying_keys.push(evaluate_polynomial_commitment(
                &identifiers[i],
                &total_polynomial_commitment,
            ));
        }

        let dkg_output_content =
            DKGOutputContent::new(PublicKey::from_point(group_point), verifying_keys);
        let mut dkg_output_transcript = Transcript::new(b"dkg output");
        dkg_output_transcript.append_message(b"content", &dkg_output_content.to_bytes());

        let signature = self.sign(dkg_output_transcript);
        let dkg_output = DKGOutput::new(self.public, dkg_output_content, signature);

        Ok((dkg_output, total_secret_share))
    }
}
