//! Implementation of the SimplPedPoP protocol (<https://eprint.iacr.org/2023/899>), a spp based on PedPoP, which in turn is based
//! on Pedersen's spp. All of them have as the fundamental building block the Shamir's Secret Sharing scheme.

#![allow(clippy::result_large_err)]

mod types;
pub mod errors;

pub use self::types::{AllMessage, SPPOutputMessage, SPPOutput};
pub(crate) use self::types::{PolynomialCommitment, MessageContent, Parameters};
use alloc::vec::Vec;
use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use merlin::Transcript;
use rand_core::RngCore;
use crate::{
    context::SigningTranscript, verify_batch, Keypair, PublicKey, SecretKey, getrandom_or_panic,
};
use self::{
    errors::{SPPError, SPPResult},
    types::{
        SecretPolynomial, SecretShare, CHACHA20POLY1305_KEY_LENGTH, ENCRYPTION_NONCE_LENGTH,
        RECIPIENTS_HASH_LENGTH,
    },
};
use super::{ThresholdPublicKey, Identifier, SigningKeypair, VerifyingShare, GENERATOR};

impl Keypair {
    /// First round of the SimplPedPoP protocol.
    ///
    /// We do not recipients.sort() because the protocol is simpler
    /// if we require that all contributions provide the list in
    /// exactly the same order.
    ///
    /// Instead we create a kind of session id by hashing the list
    /// provided, but we provide only hash to recipients, not the
    /// full recipients list.
    pub fn simplpedpop_contribute_all(
        &self,
        threshold: u16,
        recipients: Vec<PublicKey>,
    ) -> SPPResult<AllMessage> {
        let parameters = Parameters::generate(recipients.len() as u16, threshold);
        parameters.validate()?;

        let mut rng = getrandom_or_panic();

        let mut recipients_transcript = Transcript::new(b"RecipientsHash");
        parameters.commit(&mut recipients_transcript);

        for recipient in &recipients {
            recipients_transcript.commit_point(b"recipient", recipient.as_compressed());
        }

        let mut recipients_hash = [0u8; RECIPIENTS_HASH_LENGTH];
        recipients_transcript.challenge_bytes(b"finalize", &mut recipients_hash);

        let secret_polynomial =
            SecretPolynomial::generate(parameters.threshold as usize - 1, &mut rng);

        let mut encrypted_secret_shares = Vec::new();

        let polynomial_commitment = secret_polynomial.commit();

        let mut encryption_transcript = merlin::Transcript::new(b"Encryption");
        parameters.commit(&mut encryption_transcript);
        encryption_transcript.commit_point(b"contributor", self.public.as_compressed());

        let mut encryption_nonce = [0u8; ENCRYPTION_NONCE_LENGTH];
        rng.fill_bytes(&mut encryption_nonce);
        encryption_transcript.append_message(b"nonce", &encryption_nonce);

        let ephemeral_key = Keypair::generate();

        for i in 0..parameters.participants {
            let identifier = Identifier::generate(&recipients_hash, i);

            let polynomial_evaluation = secret_polynomial.evaluate(&identifier.0);

            let secret_share = SecretShare(polynomial_evaluation);

            let recipient = recipients[i as usize];

            let key_exchange = ephemeral_key.secret.key * recipient.into_point();

            let mut encryption_transcript = encryption_transcript.clone();
            encryption_transcript.commit_point(b"recipient", recipient.as_compressed());
            encryption_transcript.commit_point(b"key exchange", &key_exchange.compress());
            encryption_transcript.append_message(b"i", &(i as usize).to_le_bytes());

            let mut key_bytes = [0; CHACHA20POLY1305_KEY_LENGTH];
            encryption_transcript.challenge_bytes(b"key", &mut key_bytes);

            let encrypted_secret_share = secret_share.encrypt(&key_bytes, &encryption_nonce)?;

            encrypted_secret_shares.push(encrypted_secret_share);
        }

        let pk = &PublicKey::from_point(
            *polynomial_commitment
                .coefficients_commitments
                .first()
                .expect("This never fails because the minimum threshold is 2"),
        );

        let secret = *secret_polynomial
            .coefficients
            .first()
            .expect("This never fails because the minimum threshold is 2");

        let mut nonce: [u8; 32] = [0u8; 32];
        crate::getrandom_or_panic().fill_bytes(&mut nonce);

        let secret_key = SecretKey { key: secret, nonce };

        let message_content = MessageContent::new(
            self.public,
            encryption_nonce,
            parameters,
            recipients_hash,
            polynomial_commitment,
            encrypted_secret_shares,
            ephemeral_key.public,
        );

        let mut signature_transcript = Transcript::new(b"signature");
        signature_transcript.append_message(b"message_sig", &message_content.to_bytes());
        let signature = self.sign(signature_transcript);

        let mut pop_transcript = Transcript::new(b"pop");
        pop_transcript.append_message(b"message_pop", &message_content.to_bytes());
        let proof_of_possession = secret_key.sign(pop_transcript, pk);

        Ok(AllMessage::new(message_content, signature, proof_of_possession))
    }

    /// Second round of the SimplPedPoP protocol.
    pub fn simplpedpop_recipient_all(
        &self,
        messages: &[AllMessage],
    ) -> SPPResult<(SPPOutputMessage, SigningKeypair)> {
        if messages.is_empty() {
            return Err(SPPError::EmptyMessages);
        }

        let first_message = &messages[0];
        let parameters = &first_message.content.parameters;
        let threshold = parameters.threshold as usize;
        let participants = parameters.participants as usize;

        first_message.content.parameters.validate()?;

        if messages.len() < participants {
            return Err(SPPError::InvalidNumberOfMessages);
        }

        let mut secret_shares = Vec::with_capacity(participants);
        let mut verifying_keys = Vec::with_capacity(participants);
        let mut senders = Vec::with_capacity(participants);
        let mut signatures = Vec::with_capacity(participants);
        let mut signatures_transcripts = Vec::with_capacity(participants);
        let mut group_point = RistrettoPoint::identity();
        let mut total_secret_share = Scalar::ZERO;
        let mut total_polynomial_commitment =
            PolynomialCommitment { coefficients_commitments: vec![] };
        let mut identifiers = Vec::new();
        let mut public_keys = Vec::with_capacity(participants);
        let mut proofs_of_possession = Vec::with_capacity(participants);
        let mut pops_transcripts = Vec::with_capacity(participants);

        for (j, message) in messages.iter().enumerate() {
            if &message.content.parameters != parameters {
                return Err(SPPError::DifferentParameters);
            }
            if message.content.recipients_hash != first_message.content.recipients_hash {
                return Err(SPPError::DifferentRecipientsHash);
            }

            let content = &message.content;
            let polynomial_commitment = &content.polynomial_commitment;
            let encrypted_secret_shares = &content.encrypted_secret_shares;

            let public_key = PublicKey::from_point(
                *polynomial_commitment
                    .coefficients_commitments
                    .first()
                    .expect("This never fails because the minimum threshold is 2"),
            );
            public_keys.push(public_key);
            proofs_of_possession.push(message.proof_of_possession);

            senders.push(content.sender);
            signatures.push(message.signature);

            let mut encryption_transcript = Transcript::new(b"Encryption");
            parameters.commit(&mut encryption_transcript);
            encryption_transcript.commit_point(b"contributor", content.sender.as_compressed());
            encryption_transcript.append_message(b"nonce", &content.encryption_nonce);

            if polynomial_commitment.coefficients_commitments.len() != threshold {
                return Err(SPPError::IncorrectNumberOfCoefficientCommitments);
            }

            if encrypted_secret_shares.len() != participants {
                return Err(SPPError::IncorrectNumberOfEncryptedShares);
            }

            let mut signature_transcript = Transcript::new(b"signature");
            signature_transcript.append_message(b"message_sig", &content.to_bytes());
            signatures_transcripts.push(signature_transcript);

            let mut pop_transcript = Transcript::new(b"pop");
            pop_transcript.append_message(b"message_pop", &content.to_bytes());
            pops_transcripts.push(pop_transcript);

            let secret_commitment = polynomial_commitment
                .coefficients_commitments
                .first()
                .expect("This never fails because the minimum threshold is 2");

            total_polynomial_commitment = PolynomialCommitment::sum_polynomial_commitments(&[
                &total_polynomial_commitment,
                &polynomial_commitment,
            ]);

            let key_exchange = self.secret.key * message.content.ephemeral_key.as_point();

            encryption_transcript.commit_point(b"recipient", self.public.as_compressed());
            encryption_transcript.commit_point(b"key exchange", &key_exchange.compress());

            let mut secret_share_found = false;

            for (i, encrypted_secret_share) in encrypted_secret_shares.iter().enumerate() {
                let mut encryption_transcript = encryption_transcript.clone();

                encryption_transcript.append_message(b"i", &i.to_le_bytes());

                let mut key_bytes = [0; CHACHA20POLY1305_KEY_LENGTH];
                encryption_transcript.challenge_bytes(b"key", &mut key_bytes);

                if identifiers.len() != participants {
                    let identifier =
                        Identifier::generate(&first_message.content.recipients_hash, i as u16);
                    identifiers.push(identifier);
                }

                if !secret_share_found {
                    if let Ok(secret_share) = SecretShare::decrypt(
                        encrypted_secret_share,
                        &key_bytes,
                        &content.encryption_nonce,
                    ) {
                        if secret_share.0 * GENERATOR
                            == polynomial_commitment.evaluate(&identifiers[i].0)
                        {
                            secret_shares.push(secret_share);
                            secret_share_found = true;
                        }
                    }
                }
            }

            total_secret_share += secret_shares
                .get(j)
                .ok_or(SPPError::InvalidSecretShare { culprit: message.content.sender })?
                .0;
            group_point += secret_commitment;
        }

        verify_batch(&mut pops_transcripts, &proofs_of_possession, &public_keys, false)
            .map_err(SPPError::InvalidProofOfPossession)?;

        verify_batch(&mut signatures_transcripts, &signatures, &senders, false)
            .map_err(SPPError::InvalidSignature)?;

        for id in &identifiers {
            let evaluation = total_polynomial_commitment.evaluate(&id.0);
            verifying_keys.push((*id, VerifyingShare(PublicKey::from_point(evaluation))));
        }

        let spp_output = SPPOutput::new(
            parameters,
            ThresholdPublicKey(PublicKey::from_point(group_point)),
            verifying_keys,
        );

        let mut spp_output_transcript = Transcript::new(b"spp output");
        spp_output_transcript.append_message(b"message", &spp_output.to_bytes());

        let signature = self.sign(spp_output_transcript);
        let spp_output = SPPOutputMessage::new(VerifyingShare(self.public), spp_output, signature);

        let mut nonce: [u8; 32] = [0u8; 32];
        getrandom_or_panic().fill_bytes(&mut nonce);

        let secret_key = SecretKey { key: total_secret_share, nonce };

        let keypair = Keypair::from(secret_key);

        Ok((spp_output, SigningKeypair(keypair)))
    }
}

#[cfg(test)]
mod tests {
    use crate::olaf::simplpedpop::types::AllMessage;
    use crate::olaf::test_utils::generate_parameters;
    use crate::{Keypair, PublicKey};
    use alloc::vec::Vec;

    const PROTOCOL_RUNS: usize = 1;

    #[test]
    fn test_simplpedpop_protocol() {
        for _ in 0..PROTOCOL_RUNS {
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

            let mut spp_outputs = Vec::new();

            for kp in keypairs.iter() {
                let spp_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();
                spp_output.0.verify_signature().unwrap();
                spp_outputs.push(spp_output);
            }

            // Verify that all threshold_public_keys and verifying_keys are equal
            assert!(
                spp_outputs.windows(2).all(|w| w[0].0.spp_output.threshold_public_key.0
                    == w[1].0.spp_output.threshold_public_key.0
                    && w[0].0.spp_output.verifying_keys.len()
                        == w[1].0.spp_output.verifying_keys.len()
                    && w[0]
                        .0
                        .spp_output
                        .verifying_keys
                        .iter()
                        .zip(w[1].0.spp_output.verifying_keys.iter())
                        .all(|((a, b), (c, d))| a.0 == c.0 && b.0 == d.0)),
                "All spp outputs should have identical group public keys and verifying keys."
            );

            // Verify that all verifying_shares are valid
            for i in 0..participants {
                for j in 0..participants {
                    assert_eq!(
                        spp_outputs[i].0.spp_output.verifying_keys[j].1 .0,
                        (spp_outputs[j].1 .0.public),
                        "Verification of total secret shares failed!"
                    );
                }
            }
        }
    }
}
