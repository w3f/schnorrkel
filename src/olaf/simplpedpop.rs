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
    GENERATOR, MINIMUM_THRESHOLD,
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
        // provided, but we provide only hash to recipiants, not the
        // full recipiants list.
        let mut t = merlin::Transcript::new(b"RecipientsHash");
        parameters.commit(&mut t);
        for r in recipients.iter() {
            t.commit_point(b"recipient", r.as_compressed());
        }
        let mut recipients_hash = [0u8; RECIPIENTS_HASH_LENGTH];
        t.challenge_bytes(b"finalize", &mut recipients_hash);

        let coefficients = generate_coefficients(parameters.threshold as usize - 1, &mut rng);
        let mut scalar_evaluations = Vec::new();

        for i in 0..parameters.participants {
            let identifier = generate_identifier(&recipients_hash, i);
            let scalar_evaluation = evaluate_polynomial(&identifier, &coefficients);
            scalar_evaluations.push(scalar_evaluation);
        }

        // Create the vector of commitments
        let point_polynomial: Vec<RistrettoPoint> =
            coefficients.iter().map(|c| GENERATOR * *c).collect();

        let mut enc0 = merlin::Transcript::new(b"Encryption");
        parameters.commit(&mut enc0);
        enc0.commit_point(b"contributor", self.public.as_compressed());

        let mut encryption_nonce = [0u8; ENCRYPTION_NONCE_LENGTH];
        rng.fill_bytes(&mut encryption_nonce);
        enc0.append_message(b"nonce", &encryption_nonce);

        let ephemeral_key = Keypair::generate();

        let mut ciphertexts = Vec::new();

        for i in 0..parameters.participants {
            let ciphertext = encrypt(
                &scalar_evaluations[i as usize],
                &ephemeral_key.secret.key,
                enc0.clone(),
                &recipients[i as usize],
                &encryption_nonce,
                i as usize,
            )?;

            ciphertexts.push(ciphertext);
        }

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

        let mut t_pop = Transcript::new(b"pop");
        t_pop.append_message(b"secret commitment", secret_commitment.compress().as_bytes());
        let proof_of_possession = secret_key.sign(t_pop, pk);

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

        let mut t_sig = Transcript::new(b"signature");
        t_sig.append_message(b"message", &message_content.to_bytes());
        let signature = self.sign(t_sig);

        Ok(AllMessage::new(message_content, signature))
    }

    /// Second round of the SimplPedPoP protocol.
    pub fn simplpedpop_recipient_all(
        &self,
        messages: &[AllMessage],
    ) -> DKGResult<(DKGOutput, Scalar)> {
        if messages.len() < MINIMUM_THRESHOLD as usize {
            return Err(DKGError::InvalidNumberOfMessages);
        }

        let participants = messages[0].content.parameters.participants as usize;
        let threshold = messages[0].content.parameters.threshold as usize;

        if messages.len() != participants {
            return Err(DKGError::IncorrectNumberOfMessages);
        }

        messages[0].content.parameters.validate()?;

        let first_params = &messages[0].content.parameters;
        let recipients_hash = &messages[0].content.recipients_hash;

        let mut secret_shares = Vec::new();

        let mut verifying_keys = Vec::new();

        let mut public_keys = Vec::with_capacity(participants);
        let mut proofs_of_possession = Vec::with_capacity(participants);

        let mut senders = Vec::with_capacity(participants);
        let mut signatures = Vec::with_capacity(participants);

        let mut t_sigs = Vec::with_capacity(participants);
        let mut t_pops = Vec::with_capacity(participants);

        let mut group_point = RistrettoPoint::identity();
        let mut total_secret_share = Scalar::ZERO;
        let mut total_polynomial_commitment: Vec<RistrettoPoint> = Vec::new();

        for (j, message) in messages.iter().enumerate() {
            if &message.content.parameters != first_params {
                return Err(DKGError::DifferentParameters);
            }
            if &message.content.recipients_hash != recipients_hash {
                return Err(DKGError::DifferentRecipientsHash);
            }
            // The public keys are the secret commitments of the participants
            let public_key =
                PublicKey::from_point(
                    *message.content.point_polynomial.first().expect(
                        "This never fails because the minimum threshold of the protocol is 2",
                    ),
                );

            public_keys.push(public_key);
            proofs_of_possession.push(message.content.proof_of_possession);

            senders.push(message.content.sender);
            signatures.push(message.signature);

            // Recreate the encryption environment
            let mut enc = merlin::Transcript::new(b"Encryption");
            message.content.parameters.commit(&mut enc);
            enc.commit_point(b"contributor", message.content.sender.as_compressed());

            let point_polynomial = &message.content.point_polynomial;
            let ciphertexts = &message.content.ciphertexts;

            if point_polynomial.len() != threshold - 1 {
                return Err(DKGError::IncorrectNumberOfCommitments);
            }

            if ciphertexts.len() != participants {
                return Err(DKGError::IncorrectNumberOfEncryptedShares);
            }

            let encryption_nonce = message.content.encryption_nonce;
            enc.append_message(b"nonce", &encryption_nonce);

            let message_bytes = &message.content.to_bytes();

            let mut t_sig = Transcript::new(b"signature");
            t_sig.append_message(b"message", message_bytes);

            let mut t_pop = Transcript::new(b"pop");
            let secret_commitment = point_polynomial
                .first()
                .expect("This never fails because the minimum threshold is 2");
            t_pop.append_message(b"secret commitment", secret_commitment.compress().as_bytes());

            t_sigs.push(t_sig);
            t_pops.push(t_pop);

            if total_polynomial_commitment.is_empty() {
                total_polynomial_commitment = point_polynomial.clone();
            } else {
                total_polynomial_commitment =
                    sum_commitments(&[&total_polynomial_commitment, point_polynomial])?;
            }

            let ephemeral_key = message.content.ephemeral_key;
            let key_exchange = self.secret.key * message.content.ephemeral_key.into_point();

            for (i, ciphertext) in ciphertexts.iter().enumerate() {
                let identifier = generate_identifier(recipients_hash, i as u16);

                if let Ok(secret_share) = decrypt(
                    enc.clone(),
                    &ephemeral_key,
                    &self.public,
                    &key_exchange,
                    ciphertext,
                    &encryption_nonce,
                    i,
                ) {
                    if secret_share * GENERATOR
                        == evaluate_polynomial_commitment(&identifier, point_polynomial)
                    {
                        secret_shares.push(secret_share);
                        break;
                    }
                }
            }

            total_secret_share += secret_shares[j];

            group_point += secret_commitment;
        }

        for i in 0..participants {
            let identifier = generate_identifier(recipients_hash, i as u16);
            verifying_keys
                .push(evaluate_polynomial_commitment(&identifier, &total_polynomial_commitment));
        }

        if secret_shares.len() != messages[0].content.parameters.participants as usize {
            return Err(DKGError::IncorrectNumberOfValidSecretShares {
                expected: messages[0].content.parameters.participants as usize,
                actual: secret_shares.len(),
            });
        }

        verify_batch(t_pops, &proofs_of_possession[..], &public_keys[..], false)
            .map_err(DKGError::InvalidProofOfPossession)?;

        verify_batch(t_sigs, &signatures[..], &senders[..], false)
            .map_err(DKGError::InvalidSignature)?;

        let dkg_output_content =
            DKGOutputContent::new(PublicKey::from_point(group_point), verifying_keys);

        let mut transcript = Transcript::new(b"dkg output");
        transcript.append_message(b"content", &dkg_output_content.to_bytes());

        let signature = self.sign(transcript);

        let dkg_output = DKGOutput::new(self.public, dkg_output_content, signature);

        Ok((dkg_output, total_secret_share))
    }
}
