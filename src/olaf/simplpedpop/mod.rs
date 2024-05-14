//! Implementation of the SimplPedPoP protocol (<https://eprint.iacr.org/2023/899>), a DKG based on PedPoP, which in turn is based
//! on Pedersen's DKG. All of them have as the fundamental building block the Shamir's Secret Sharing scheme.

mod types;
mod errors;

pub use self::types::{
    AllMessage, DKGOutput, DKGOutputMessage, MessageContent, Parameters, PolynomialCommitment,
};

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
use super::{GroupPublicKey, Identifier, SigningKeypair, VerifyingShare, GENERATOR};

impl Keypair {
    /// First round of the SimplPedPoP protocol.
    pub fn simplpedpop_contribute_all(
        &self,
        threshold: u16,
        recipients: Vec<PublicKey>,
    ) -> SPPResult<AllMessage> {
        let parameters = Parameters::generate(recipients.len() as u16, threshold);
        parameters.validate()?;

        let mut rng = getrandom_or_panic();

        // We do not recipients.sort() because the protocol is simpler
        // if we require that all contributions provide the list in
        // exactly the same order.
        //
        // Instead we create a kind of session id by hashing the list
        // provided, but we provide only hash to recipients, not the
        // full recipients list.
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

        let secret_commitment = polynomial_commitment
            .coefficients_commitments
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
            polynomial_commitment,
            encrypted_secret_shares,
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
    ) -> SPPResult<(DKGOutputMessage, SigningKeypair)> {
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
            proofs_of_possession.push(content.proof_of_possession);

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
            signature_transcript.append_message(b"message", &content.to_bytes());
            signatures_transcripts.push(signature_transcript);

            let mut pop_transcript = Transcript::new(b"pop");

            let secret_commitment = polynomial_commitment
                .coefficients_commitments
                .first()
                .expect("This never fails because the minimum threshold is 2");

            pop_transcript
                .append_message(b"secret commitment", secret_commitment.compress().as_bytes());

            pops_transcripts.push(pop_transcript);

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

            total_secret_share += secret_shares.get(j).ok_or(SPPError::InvalidSecretShare)?.0;
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

        let dkg_output = DKGOutput::new(
            parameters,
            GroupPublicKey(PublicKey::from_point(group_point)),
            verifying_keys,
        );

        let mut dkg_output_transcript = Transcript::new(b"dkg output");
        dkg_output_transcript.append_message(b"message", &dkg_output.to_bytes());

        let signature = self.sign(dkg_output_transcript);
        let dkg_output = DKGOutputMessage::new(self.public, dkg_output, signature);

        let mut nonce: [u8; 32] = [0u8; 32];
        getrandom_or_panic().fill_bytes(&mut nonce);

        let secret_key = SecretKey { key: total_secret_share, nonce };

        let keypair = Keypair::from(secret_key);

        Ok((dkg_output, SigningKeypair(keypair)))
    }
}

#[cfg(test)]
mod tests {
    mod simplpedpop {
        use crate::olaf::simplpedpop::errors::SPPError;
        use crate::olaf::simplpedpop::types::{
            AllMessage, EncryptedSecretShare, Parameters, CHACHA20POLY1305_LENGTH,
            RECIPIENTS_HASH_LENGTH,
        };
        use crate::olaf::MINIMUM_THRESHOLD;
        use crate::{Keypair, PublicKey};
        use alloc::vec::Vec;
        use curve25519_dalek::ristretto::RistrettoPoint;
        use curve25519_dalek::traits::Identity;
        use merlin::Transcript;
        use rand::Rng;

        const MAXIMUM_PARTICIPANTS: u16 = 10;
        const MINIMUM_PARTICIPANTS: u16 = 2;
        const PROTOCOL_RUNS: usize = 1;

        fn generate_parameters() -> Parameters {
            let mut rng = rand::thread_rng();
            let participants = rng.gen_range(MINIMUM_PARTICIPANTS..=MAXIMUM_PARTICIPANTS);
            let threshold = rng.gen_range(MINIMUM_THRESHOLD..=participants);

            Parameters { participants, threshold }
        }

        #[test]
        fn test_simplpedpop_protocol() {
            for _ in 0..PROTOCOL_RUNS {
                let parameters = generate_parameters();
                let participants = parameters.participants as usize;
                let threshold = parameters.threshold as usize;

                let keypairs: Vec<Keypair> =
                    (0..participants).map(|_| Keypair::generate()).collect();
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

                // Verify that all DKG outputs are equal for group_public_key and verifying_keys
                assert!(
                    dkg_outputs.windows(2).all(|w| w[0].0.dkg_output.group_public_key.0
                        == w[1].0.dkg_output.group_public_key.0
                        && w[0].0.dkg_output.verifying_keys.len()
                            == w[1].0.dkg_output.verifying_keys.len()
                        && w[0]
                            .0
                            .dkg_output
                            .verifying_keys
                            .iter()
                            .zip(w[1].0.dkg_output.verifying_keys.iter())
                            .all(|((a, b), (c, d))| a.0 == c.0 && b.0 == d.0)),
                    "All DKG outputs should have identical group public keys and verifying keys."
                );

                // Verify that all verifying_shares are valid
                for i in 0..participants {
                    for j in 0..participants {
                        assert_eq!(
                            dkg_outputs[i].0.dkg_output.verifying_keys[j].1 .0,
                            (dkg_outputs[j].1 .0.public),
                            "Verification of total secret shares failed!"
                        );
                    }
                }
            }
        }

        #[test]
        fn test_invalid_number_of_messages() {
            let threshold = 3;
            let participants = 5;

            let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

            let mut messages: Vec<AllMessage> = keypairs
                .iter()
                .map(|kp| kp.simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap())
                .collect();

            messages.pop();

            let result = keypairs[0].simplpedpop_recipient_all(&messages);

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => match e {
                    SPPError::InvalidNumberOfMessages => assert!(true),
                    _ => {
                        panic!("Expected DKGError::InvalidNumberOfMessages, but got {:?}", e)
                    },
                },
            }
        }

        #[test]
        fn test_different_parameters() {
            let threshold = 3;
            let participants = 5;

            let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

            let mut messages: Vec<AllMessage> = Vec::new();
            for i in 0..participants {
                let message =
                    keypairs[i].simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap();
                messages.push(message);
            }

            messages[1].content.parameters.threshold += 1;

            let result = keypairs[0].simplpedpop_recipient_all(&messages);

            // Check if the result is an error
            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => match e {
                    SPPError::DifferentParameters => assert!(true),
                    _ => panic!("Expected DKGError::DifferentParameters, but got {:?}", e),
                },
            }
        }

        #[test]
        fn test_different_recipients_hash() {
            let threshold = 3;
            let participants = 5;

            let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

            let mut messages: Vec<AllMessage> = keypairs
                .iter()
                .map(|kp| kp.simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap())
                .collect();

            messages[1].content.recipients_hash = [1; RECIPIENTS_HASH_LENGTH];

            let result = keypairs[0].simplpedpop_recipient_all(&messages);

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => match e {
                    SPPError::DifferentRecipientsHash => assert!(true),
                    _ => {
                        panic!("Expected DKGError::DifferentRecipientsHash, but got {:?}", e)
                    },
                },
            }
        }

        #[test]
        fn test_incorrect_number_of_commitments() {
            let threshold = 3;
            let participants = 5;

            let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

            let mut messages: Vec<AllMessage> = keypairs
                .iter()
                .map(|kp| kp.simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap())
                .collect();

            messages[1].content.polynomial_commitment.coefficients_commitments.pop();

            let result = keypairs[0].simplpedpop_recipient_all(&messages);

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => match e {
                    SPPError::IncorrectNumberOfCoefficientCommitments => assert!(true),
                    _ => panic!(
                        "Expected DKGError::IncorrectNumberOfCoefficientCommitments, but got {:?}",
                        e
                    ),
                },
            }
        }

        #[test]
        fn test_incorrect_number_of_encrypted_shares() {
            let threshold = 3;
            let participants = 5;

            let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

            let mut messages: Vec<AllMessage> = keypairs
                .iter()
                .map(|kp| kp.simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap())
                .collect();

            messages[1].content.encrypted_secret_shares.pop();

            let result = keypairs[0].simplpedpop_recipient_all(&messages);

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => match e {
                    SPPError::IncorrectNumberOfEncryptedShares => assert!(true),
                    _ => panic!(
                        "Expected DKGError::IncorrectNumberOfEncryptedShares, but got {:?}",
                        e
                    ),
                },
            }
        }

        #[test]
        fn test_invalid_secret_share() {
            let threshold = 3;
            let participants = 5;

            let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

            let mut messages: Vec<AllMessage> = keypairs
                .iter()
                .map(|kp| kp.simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap())
                .collect();

            messages[1].content.encrypted_secret_shares[0] =
                EncryptedSecretShare(vec![1; CHACHA20POLY1305_LENGTH]);

            let result = keypairs[0].simplpedpop_recipient_all(&messages);

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => match e {
                    SPPError::InvalidSecretShare => assert!(true),
                    _ => panic!("Expected DKGError::InvalidSecretShare, but got {:?}", e),
                },
            }
        }

        #[test]
        fn test_invalid_signature() {
            let threshold = 3;
            let participants = 5;

            let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

            let mut messages: Vec<AllMessage> = keypairs
                .iter()
                .map(|kp| kp.simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap())
                .collect();

            messages[1].signature =
                keypairs[1].secret.sign(Transcript::new(b"invalid"), &keypairs[1].public);

            let result = keypairs[0].simplpedpop_recipient_all(&messages);

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => match e {
                    SPPError::InvalidSignature(_) => assert!(true),
                    _ => panic!("Expected DKGError::InvalidSignature, but got {:?}", e),
                },
            }
        }

        #[test]
        fn test_invalid_threshold() {
            let keypair = Keypair::generate();
            let result = keypair.simplpedpop_contribute_all(
                1,
                vec![
                    PublicKey::from_point(RistrettoPoint::identity()),
                    PublicKey::from_point(RistrettoPoint::identity()),
                ],
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => match e {
                    SPPError::InsufficientThreshold => assert!(true),
                    _ => panic!("Expected SPPError::InsufficientThreshold, but got {:?}", e),
                },
            }
        }

        #[test]
        fn test_invalid_participants() {
            let keypair = Keypair::generate();
            let result = keypair.simplpedpop_contribute_all(
                2,
                vec![PublicKey::from_point(RistrettoPoint::identity())],
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => match e {
                    SPPError::InvalidNumberOfParticipants => {
                        assert!(true)
                    },
                    _ => {
                        panic!("Expected SPPError::InvalidNumberOfParticipants, but got {:?}", e)
                    },
                },
            }
        }

        #[test]
        fn test_threshold_greater_than_participants() {
            let keypair = Keypair::generate();
            let result = keypair.simplpedpop_contribute_all(
                3,
                vec![
                    PublicKey::from_point(RistrettoPoint::identity()),
                    PublicKey::from_point(RistrettoPoint::identity()),
                ],
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => match e {
                    SPPError::ExcessiveThreshold => assert!(true),
                    _ => panic!("Expected SPPError::ExcessiveThreshold), but got {:?}", e),
                },
            }
        }
    }
}
