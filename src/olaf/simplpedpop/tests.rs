#[cfg(test)]
mod tests {
    mod simplpedpop {
        use crate::olaf::simplpedpop::{AllMessage, RECIPIENTS_HASH_LENGTH, Parameters};
        use crate::olaf::simplpedpop::DKGError;
        use crate::{Keypair, PublicKey};
        use alloc::vec::Vec;
        use curve25519_dalek::ristretto::RistrettoPoint;
        use curve25519_dalek::traits::Identity;
        use merlin::Transcript;
        use rand::Rng;
        use crate::olaf::MINIMUM_THRESHOLD;
        use crate::olaf::simplpedpop::types::{EncryptedSecretShare, CHACHA20POLY1305_LENGTH};

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
                            (dkg_outputs[j].1 .0.to_public()),
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
                    DKGError::InvalidNumberOfMessages => assert!(true),
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
                    DKGError::DifferentParameters => assert!(true),
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
                    DKGError::DifferentRecipientsHash => assert!(true),
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
                    DKGError::IncorrectNumberOfCoefficientCommitments => assert!(true),
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
                    DKGError::IncorrectNumberOfEncryptedShares => assert!(true),
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
                    DKGError::InvalidSecretShare => assert!(true),
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
                    DKGError::InvalidSignature(_) => assert!(true),
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
                    DKGError::InsufficientThreshold => assert!(true),
                    _ => panic!("Expected DKGError::InsufficientThreshold, but got {:?}", e),
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
                    DKGError::InvalidNumberOfParticipants => assert!(true),
                    _ => {
                        panic!("Expected DKGError::InvalidNumberOfParticipants, but got {:?}", e)
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
                    DKGError::ExcessiveThreshold => assert!(true),
                    _ => panic!("Expected DKGError::ExcessiveThreshold, but got {:?}", e),
                },
            }
        }
    }
}
