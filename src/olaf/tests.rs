#[cfg(test)]
mod tests {
    use crate::olaf::{
        errors::DKGResult,
        identifier::Identifier,
        keys::{GroupPublicKey, GroupPublicKeyShare},
        simplpedpop::{
            self,
            round1::{self, PrivateData, PublicData, PublicMessage},
            round2::{self, Messages},
            round3, Identifiers, Parameters,
        },
    };
    use alloc::{
        collections::{BTreeMap, BTreeSet},
        vec::Vec,
    };
    use merlin::Transcript;
    use rand::{rngs::OsRng, Rng};

    const MAXIMUM_PARTICIPANTS: u16 = 10;
    const MINIMUM_PARTICIPANTS: u16 = 3;
    const MININUM_THRESHOLD: u16 = 2;
    const PROTOCOL_RUNS: usize = 1;

    fn generate_parameters() -> Vec<Parameters> {
        let mut rng = rand::thread_rng();
        let max_signers = rng.gen_range(MINIMUM_PARTICIPANTS..=MAXIMUM_PARTICIPANTS);
        let min_signers = rng.gen_range(MININUM_THRESHOLD..=max_signers);

        (1..=max_signers).map(|_| Parameters::new(max_signers, min_signers)).collect()
    }

    fn round1() -> (Vec<Parameters>, Vec<PrivateData>, Vec<PublicData>, Vec<BTreeSet<PublicMessage>>)
    {
        let parameters_list = generate_parameters();

        let mut all_public_messages_vec = Vec::new();
        let mut participants_round1_private_data = Vec::new();
        let mut participants_round1_public_data = Vec::new();

        for i in 0..parameters_list.len() {
            let (private_data, public_message, public_data) =
                round1::run(parameters_list[i as usize].clone(), OsRng)
                    .expect("Round 1 should complete without errors!");

            all_public_messages_vec.push(public_message.clone());
            participants_round1_public_data.push(public_data);
            participants_round1_private_data.push(private_data);
        }

        let mut received_round1_public_messages: Vec<BTreeSet<PublicMessage>> = Vec::new();

        let mut all_public_messages = BTreeSet::new();

        for i in 0..parameters_list[0].participants {
            all_public_messages.insert(all_public_messages_vec[i as usize].clone());
        }

        // Iterate through each participant to create a set of messages excluding their own.
        for i in 0..parameters_list[0].participants {
            let own_message = PublicMessage::new(&participants_round1_public_data[i as usize]);

            let mut messages_for_participant = BTreeSet::new();

            for message in &all_public_messages {
                if &own_message != message {
                    // Exclude the participant's own message.
                    messages_for_participant.insert(message.clone());
                }
            }

            received_round1_public_messages.push(messages_for_participant);
        }

        (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            received_round1_public_messages,
        )
    }

    fn round2(
        parameters_list: &Vec<Parameters>,
        participants_round1_private_data: Vec<PrivateData>,
        participants_round1_public_data: &Vec<PublicData>,
        participants_round1_public_messages: &Vec<BTreeSet<PublicMessage>>,
    ) -> DKGResult<(Vec<round2::PublicData>, Vec<Messages>, Vec<Identifiers>, Vec<Identifier>)>
    {
        let mut participants_round2_public_data = Vec::new();
        let mut participants_round2_public_messages = Vec::new();
        let mut participants_set_of_participants = Vec::new();
        let mut identifiers_vec = Vec::new();

        for i in 0..parameters_list[0].participants {
            let result = simplpedpop::round2::run(
                participants_round1_private_data[i as usize].clone(),
                &participants_round1_public_data[i as usize].clone(),
                participants_round1_public_messages[i as usize].clone(),
                Transcript::new(b"simplpedpop"),
            )?;

            participants_round2_public_data.push(result.0.clone());
            participants_round2_public_messages.push(result.1);
            participants_set_of_participants.push(result.0.identifiers.clone());
            identifiers_vec.push(result.0.identifiers.own_identifier);
        }

        Ok((
            participants_round2_public_data,
            participants_round2_public_messages,
            participants_set_of_participants,
            identifiers_vec,
        ))
    }

    fn round3(
        participants_sets_of_participants: &Vec<Identifiers>,
        participants_round2_public_messages: &Vec<round2::PublicMessage>,
        participants_round2_public_data: &Vec<round2::PublicData>,
        participants_round1_public_data: &Vec<round1::PublicData>,
        participants_round1_private_data: Vec<round1::PrivateData>,
        participants_round2_private_messages: Vec<BTreeMap<Identifier, round2::PrivateMessage>>,
        identifiers_vec: &Vec<Identifier>,
    ) -> DKGResult<
        Vec<(GroupPublicKey, BTreeMap<Identifier, GroupPublicKeyShare>, round3::PrivateData)>,
    > {
        let mut participant_data_round3 = Vec::new();

        for i in 0..participants_sets_of_participants.len() {
            let received_round2_public_messages = participants_round2_public_messages
                .iter()
                .enumerate()
                .filter(|(index, _msg)| {
                    identifiers_vec[*index]
                        != participants_sets_of_participants[i as usize].own_identifier
                })
                .map(|(index, msg)| (identifiers_vec[index], msg.clone()))
                .collect::<BTreeMap<Identifier, round2::PublicMessage>>();

            let mut round2_private_messages: Vec<BTreeMap<Identifier, round2::PrivateMessage>> =
                Vec::new();

            for participants in participants_sets_of_participants.iter() {
                let mut messages_for_participant = BTreeMap::new();

                for (i, round_messages) in participants_round2_private_messages.iter().enumerate() {
                    if let Some(message) = round_messages.get(&participants.own_identifier) {
                        messages_for_participant.insert(identifiers_vec[i], message.clone());
                    }
                }

                round2_private_messages.push(messages_for_participant);
            }

            let result = round3::run(
                &received_round2_public_messages,
                &participants_round2_public_data[i as usize],
                &participants_round1_public_data[i as usize],
                participants_round1_private_data[i as usize].clone(),
                &round2_private_messages[i as usize],
            )?;

            participant_data_round3.push(result);
        }

        Ok(participant_data_round3)
    }

    mod simplpedpop_tests {
        use super::*;
        use crate::{
            olaf::{
                errors::DKGError,
                polynomial::{Polynomial, PolynomialCommitment},
                simplpedpop::{EncryptedSecretShare, SecretShare},
            },
            PublicKey, SecretKey, SignatureError,
        };
        use curve25519_dalek::{RistrettoPoint, Scalar};
        use simplpedpop_tests::simplpedpop::GENERATOR;

        #[test]
        pub fn test_successful_simplpedpop() {
            for _ in 0..PROTOCOL_RUNS {
                let (
                    parameters_list,
                    participants_round1_private_data,
                    participants_round1_public_data,
                    participants_round1_public_messages,
                ) = round1();

                let (
                    participants_round2_public_data,
                    participants_round2_messages,
                    participants_sets_of_participants,
                    identifiers_vec,
                ) = round2(
                    &parameters_list,
                    participants_round1_private_data.clone(),
                    &participants_round1_public_data,
                    &participants_round1_public_messages,
                )
                .unwrap();

                let participants_data_round3 = round3(
                    &participants_sets_of_participants,
                    &participants_round2_messages
                        .iter()
                        .map(|msg| msg.public_message().clone())
                        .collect(),
                    &participants_round2_public_data,
                    &participants_round1_public_data,
                    participants_round1_private_data,
                    participants_round2_messages
                        .iter()
                        .map(|msg| msg.private_messages().clone())
                        .collect(),
                    &identifiers_vec,
                )
                .unwrap();

                let shared_public_keys: Vec<GroupPublicKey> =
                    participants_data_round3.iter().map(|state| state.0).collect();

                assert!(
                    shared_public_keys.windows(2).all(|w| w[0] == w[1]),
                    "All participants must have the same group public key!"
                );

                for i in 0..parameters_list[0].participants {
                    assert_eq!(
                        participants_data_round3[i as usize]
                            .1
                            .get(&participants_sets_of_participants[i as usize].own_identifier)
                            .unwrap()
                            .compress(),
                        (participants_data_round3[i as usize].2.total_secret_share.0 * GENERATOR)
                            .compress(),
                        "Verification of total secret shares failed!"
                    );
                }
            }
        }

        #[test]
        fn test_incorrect_number_of_round1_public_messages_in_round2() {
            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                mut participants_round1_public_messages,
            ) = round1();

            participants_round1_public_messages[0].pop_last();

            let result = round2(
                &parameters_list,
                participants_round1_private_data.clone(),
                &participants_round1_public_data,
                &participants_round1_public_messages,
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::IncorrectNumberOfRound1PublicMessages {
                        expected: parameters_list[0].participants as usize - 1,
                        actual: parameters_list[0].participants as usize - 2,
                    },
                    "Expected DKGError::IncorrectNumberOfRound1PublicMessages."
                ),
            }
        }

        #[test]
        fn test_invalid_secret_polynomial_commitment_in_round2() {
            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                mut participants_round1_public_messages,
            ) = round1();

            let mut new_message = participants_round1_public_messages[0].first().unwrap().clone();

            new_message.secret_polynomial_commitment.coefficients_commitments.pop();

            participants_round1_public_messages[0].pop_first();
            participants_round1_public_messages[0].insert(new_message);

            let result = round2(
                &parameters_list,
                participants_round1_private_data.clone(),
                &participants_round1_public_data,
                &participants_round1_public_messages,
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::InvalidSecretPolynomialCommitment {
                        expected: *parameters_list[0].threshold() as usize,
                        actual: *parameters_list[0].threshold() as usize - 1,
                    },
                    "Expected DKGError::IncorrectNumberOfRound1PublicMessages."
                ),
            }
        }

        #[test]
        fn test_invalid_secret_share_error_in_round3() {
            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                participants_round1_public_messages,
            ) = round1();

            let (
                participants_round2_public_data,
                participants_round2_messages,
                participants_sets_of_participants,
                identifiers_vec,
            ) = round2(
                &parameters_list,
                participants_round1_private_data.clone(),
                &participants_round1_public_data,
                &participants_round1_public_messages,
            )
            .unwrap();

            let mut participants_round2_private_messages: Vec<
                BTreeMap<Identifier, round2::PrivateMessage>,
            > = participants_round2_messages
                .iter()
                .map(|msg| msg.private_messages().clone())
                .collect();

            let enc_keys: Vec<RistrettoPoint> = participants_round1_public_messages[1]
                .iter()
                .map(|msg| {
                    *msg.secret_polynomial_commitment.coefficients_commitments.first().unwrap()
                })
                .collect();

            let secret_share = SecretShare(Scalar::random(&mut OsRng));

            let identifiers: BTreeSet<Identifier> =
                participants_sets_of_participants[1].others_identifiers.clone();

            let index = identifiers
                .iter()
                .position(|x| x == &participants_sets_of_participants[0].own_identifier)
                .unwrap();

            let enc_share = secret_share.encrypt(
                &participants_round1_private_data[1].secret_key.key,
                &enc_keys[index],
                participants_sets_of_participants[0].own_identifier.0.as_bytes(),
            );

            let private_message = participants_round2_private_messages[1]
                .get_mut(&participants_sets_of_participants[0].own_identifier)
                .unwrap();

            private_message.encrypted_secret_share = enc_share.unwrap();

            let result = round3(
                &participants_sets_of_participants,
                &participants_round2_messages
                    .iter()
                    .map(|msg| msg.public_message().clone())
                    .collect(),
                &participants_round2_public_data,
                &participants_round1_public_data,
                participants_round1_private_data,
                participants_round2_private_messages,
                &identifiers_vec,
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::InvalidSecretShare(
                        participants_sets_of_participants[1].own_identifier
                    ),
                    "Expected DKGError::InvalidSecretShare."
                ),
            }
        }

        #[test]
        fn test_decryption_error_in_round3() {
            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                participants_round1_public_messages,
            ) = round1();

            let (
                participants_round2_public_data,
                participants_round2_messages,
                participants_sets_of_participants,
                identifiers_vec,
            ) = round2(
                &parameters_list,
                participants_round1_private_data.clone(),
                &participants_round1_public_data,
                &participants_round1_public_messages,
            )
            .unwrap();

            let mut participants_round2_private_messages: Vec<
                BTreeMap<Identifier, round2::PrivateMessage>,
            > = participants_round2_messages
                .iter()
                .map(|msg| msg.private_messages().clone())
                .collect();

            let private_message = participants_round2_private_messages[1]
                .get_mut(&participants_sets_of_participants[0].own_identifier)
                .unwrap();

            private_message.encrypted_secret_share = EncryptedSecretShare(vec![1]);

            let result = round3(
                &participants_sets_of_participants,
                &participants_round2_messages
                    .iter()
                    .map(|msg| msg.public_message().clone())
                    .collect(),
                &participants_round2_public_data,
                &participants_round1_public_data,
                participants_round1_private_data,
                participants_round2_private_messages,
                &identifiers_vec,
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::DecryptionError(chacha20poly1305::Error),
                    "Expected DKGError::DecryptionError."
                ),
            }
        }

        #[test]
        fn test_invalid_proof_of_possession_in_round2() {
            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                mut participants_round1_public_messages,
            ) = round1();

            let sk = SecretKey::generate();
            let proof_of_possession = sk.sign(
                Transcript::new(b"invalid proof of possession"),
                &PublicKey::from(sk.clone()),
            );
            let msg = PublicMessage {
                secret_polynomial_commitment: PolynomialCommitment::commit(&Polynomial::generate(
                    &mut OsRng,
                    parameters_list[0].threshold - 1,
                )),
                proof_of_possession,
            };
            participants_round1_public_messages[0].pop_last();
            participants_round1_public_messages[0].insert(msg);

            let result = round2(
                &parameters_list,
                participants_round1_private_data.clone(),
                &participants_round1_public_data,
                &participants_round1_public_messages,
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::InvalidProofOfPossession(SignatureError::EquationFalse),
                    "Expected DKGError::InvalidProofOfPossession."
                ),
            }
        }

        #[test]
        pub fn test_invalid_certificate_in_round3() {
            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                participants_round1_public_messages,
            ) = round1();

            let (
                mut participants_round2_public_data,
                participants_round2_messages,
                participants_sets_of_participants,
                identifiers_vec,
            ) = round2(
                &parameters_list,
                participants_round1_private_data.clone(),
                &participants_round1_public_data,
                &participants_round1_public_messages,
            )
            .unwrap();

            participants_round2_public_data[0].transcript = Scalar::random(&mut OsRng);

            let participants_round2_private_messages: Vec<
                BTreeMap<Identifier, round2::PrivateMessage>,
            > = participants_round2_messages
                .iter()
                .map(|msg| msg.private_messages().clone())
                .collect();

            let result = round3(
                &participants_sets_of_participants,
                &participants_round2_messages
                    .iter()
                    .map(|msg| msg.public_message().clone())
                    .collect(),
                &participants_round2_public_data,
                &participants_round1_public_data,
                participants_round1_private_data,
                participants_round2_private_messages,
                &identifiers_vec,
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::InvalidCertificate(SignatureError::EquationFalse),
                    "Expected DKGError::InvalidCertificate."
                ),
            }
        }

        #[test]
        pub fn test_incorrect_number_of_round2_public_messages_in_round3() {
            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                participants_round1_public_messages,
            ) = round1();

            let (
                participants_round2_public_data,
                participants_round2_messages,
                participants_sets_of_participants,
                identifiers_vec,
            ) = round2(
                &parameters_list,
                participants_round1_private_data.clone(),
                &participants_round1_public_data,
                &participants_round1_public_messages,
            )
            .unwrap();

            let mut participants_round2_public_messages: Vec<round2::PublicMessage> =
                participants_round2_messages
                    .iter()
                    .map(|msg| msg.public_message().clone())
                    .collect();

            participants_round2_public_messages.pop();

            let participants_round2_private_messages: Vec<
                BTreeMap<Identifier, round2::PrivateMessage>,
            > = participants_round2_messages
                .iter()
                .map(|msg| msg.private_messages().clone())
                .collect();

            let result = round3(
                &participants_sets_of_participants,
                &participants_round2_public_messages,
                &participants_round2_public_data,
                &participants_round1_public_data,
                participants_round1_private_data,
                participants_round2_private_messages,
                &identifiers_vec,
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::IncorrectNumberOfRound2PublicMessages {
                        expected: *parameters_list[0].participants() as usize - 1,
                        actual: *parameters_list[0].participants() as usize - 2
                    },
                    "Expected DKGError::IncorrectNumberOfRound2PublicMessages."
                ),
            }
        }

        #[test]
        pub fn test_incorrect_number_of_round1_public_messages_in_round3() {
            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                participants_round1_public_messages,
            ) = round1();

            let (
                mut participants_round2_public_data,
                participants_round2_messages,
                participants_sets_of_participants,
                identifiers_vec,
            ) = round2(
                &parameters_list,
                participants_round1_private_data.clone(),
                &participants_round1_public_data,
                &participants_round1_public_messages,
            )
            .unwrap();

            let participants_round2_public_messages: Vec<round2::PublicMessage> =
                participants_round2_messages
                    .iter()
                    .map(|msg| msg.public_message().clone())
                    .collect();

            participants_round2_public_data[0].round1_public_messages.pop_first();

            let participants_round2_private_messages: Vec<
                BTreeMap<Identifier, round2::PrivateMessage>,
            > = participants_round2_messages
                .iter()
                .map(|msg| msg.private_messages().clone())
                .collect();

            let result = round3(
                &participants_sets_of_participants,
                &participants_round2_public_messages,
                &participants_round2_public_data,
                &participants_round1_public_data,
                participants_round1_private_data,
                participants_round2_private_messages,
                &identifiers_vec,
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::IncorrectNumberOfRound1PublicMessages {
                        expected: *parameters_list[0].participants() as usize - 1,
                        actual: *parameters_list[0].participants() as usize - 2
                    },
                    "Expected DKGError::IncorrectNumberOfRound1PublicMessages."
                ),
            }
        }

        #[test]
        pub fn test_incorrect_number_of_round2_private_messages_in_round3() {
            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                participants_round1_public_messages,
            ) = round1();

            let (
                participants_round2_public_data,
                participants_round2_messages,
                participants_sets_of_participants,
                identifiers_vec,
            ) = round2(
                &parameters_list,
                participants_round1_private_data.clone(),
                &participants_round1_public_data,
                &participants_round1_public_messages,
            )
            .unwrap();

            let participants_round2_public_messages: Vec<round2::PublicMessage> =
                participants_round2_messages
                    .iter()
                    .map(|msg| msg.public_message().clone())
                    .collect();

            let mut participants_round2_private_messages: Vec<
                BTreeMap<Identifier, round2::PrivateMessage>,
            > = participants_round2_messages
                .iter()
                .map(|msg| msg.private_messages().clone())
                .collect();

            participants_round2_private_messages[1].pop_last();

            let result = round3(
                &participants_sets_of_participants,
                &participants_round2_public_messages,
                &participants_round2_public_data,
                &participants_round1_public_data,
                participants_round1_private_data,
                participants_round2_private_messages,
                &identifiers_vec,
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::IncorrectNumberOfRound2PrivateMessages {
                        expected: *parameters_list[0].participants() as usize - 1,
                        actual: *parameters_list[0].participants() as usize - 2
                    },
                    "Expected DKGError::IncorrectNumberOfRound2PrivateMessages."
                ),
            }
        }

        #[test]
        pub fn test_unknown_identifier_from_round2_public_messages_in_round3() {
            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                participants_round1_public_messages,
            ) = round1();

            let (
                participants_round2_public_data,
                participants_round2_messages,
                participants_sets_of_participants,
                mut identifiers_vec,
            ) = round2(
                &parameters_list,
                participants_round1_private_data.clone(),
                &participants_round1_public_data,
                &participants_round1_public_messages,
            )
            .unwrap();

            let participants_round2_public_messages: Vec<round2::PublicMessage> =
                participants_round2_messages
                    .iter()
                    .map(|msg| msg.public_message().clone())
                    .collect();

            identifiers_vec.pop();
            let unknown_identifier = Identifier(Scalar::random(&mut OsRng));
            identifiers_vec.push(unknown_identifier);

            let participants_round2_private_messages: Vec<
                BTreeMap<Identifier, round2::PrivateMessage>,
            > = participants_round2_messages
                .iter()
                .map(|msg| msg.private_messages().clone())
                .collect();

            let result = round3(
                &participants_sets_of_participants,
                &participants_round2_public_messages,
                &participants_round2_public_data,
                &participants_round1_public_data,
                participants_round1_private_data,
                participants_round2_private_messages,
                &identifiers_vec,
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::UnknownIdentifierRound2PublicMessages(unknown_identifier),
                    "Expected DKGError::UnknownIdentifierRound2PublicMessages."
                ),
            }
        }

        #[test]
        fn test_unknown_identifier_from_round2_private_messages_in_round3() {
            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                participants_round1_public_messages,
            ) = round1();

            let (
                mut participants_round2_public_data,
                participants_round2_messages,
                participants_sets_of_participants,
                identifiers_vec,
            ) = round2(
                &parameters_list,
                participants_round1_private_data.clone(),
                &participants_round1_public_data,
                &participants_round1_public_messages,
            )
            .unwrap();

            let participants_round2_public_messages: Vec<round2::PublicMessage> =
                participants_round2_messages
                    .iter()
                    .map(|msg| msg.public_message().clone())
                    .collect();

            let participants_round2_private_messages: Vec<
                BTreeMap<Identifier, round2::PrivateMessage>,
            > = participants_round2_messages
                .iter()
                .map(|msg| msg.private_messages().clone())
                .collect();

            let received_round2_public_messages = participants_round2_public_messages
                .iter()
                .enumerate()
                .filter(|(index, _msg)| {
                    identifiers_vec[*index] != participants_sets_of_participants[0].own_identifier
                })
                .map(|(index, msg)| (identifiers_vec[index], msg.clone()))
                .collect::<BTreeMap<Identifier, round2::PublicMessage>>();

            let mut round2_private_messages: Vec<BTreeMap<Identifier, round2::PrivateMessage>> =
                Vec::new();

            for participants in participants_sets_of_participants.iter() {
                let mut messages_for_participant = BTreeMap::new();

                for (i, round_messages) in participants_round2_private_messages.iter().enumerate() {
                    if let Some(message) = round_messages.get(&participants.own_identifier) {
                        messages_for_participant.insert(identifiers_vec[i], message.clone());
                    }
                }

                round2_private_messages.push(messages_for_participant);
            }

            let unknown_identifier = Identifier(Scalar::ONE);

            let private_message = round2_private_messages[0].pop_first().unwrap().1;
            round2_private_messages[0].insert(unknown_identifier, private_message);

            let public_message =
                participants_round2_public_data[0].round1_public_messages.pop_first().unwrap().1;

            participants_round2_public_data[0]
                .round1_public_messages
                .insert(unknown_identifier, public_message);

            let result = round3::run(
                &received_round2_public_messages,
                &participants_round2_public_data[0],
                &participants_round1_public_data[0],
                participants_round1_private_data[0].clone(),
                &round2_private_messages[0],
            );

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::UnknownIdentifierRound2PrivateMessages,
                    "Expected DKGError::UnknownIdentifierRound2PrivateMessages."
                ),
            }
        }

        #[test]
        fn test_invalid_threshold() {
            let parameters = Parameters::new(3, 1);
            let result = round1::run(parameters, &mut OsRng);

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::InsufficientThreshold,
                    "Expected DKGError::InsufficientThreshold."
                ),
            }
        }

        #[test]
        fn test_invalid_participants() {
            let parameters = Parameters::new(1, 2);
            let result = round1::run(parameters, &mut OsRng);

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::InvalidNumberOfParticipants,
                    "Expected DKGError::InvalidNumberOfParticipants."
                ),
            }
        }

        #[test]
        fn test_threshold_greater_than_participants() {
            let parameters = Parameters::new(2, 3);
            let result = round1::run(parameters, &mut OsRng);

            match result {
                Ok(_) => panic!("Expected an error, but got Ok."),
                Err(e) => assert_eq!(
                    e,
                    DKGError::ExcessiveThreshold,
                    "Expected DKGError::ExcessiveThreshold."
                ),
            }
        }

        #[test]
        fn test_encryption_decryption() {
            let mut rng = OsRng;
            let deckey = Scalar::random(&mut rng);
            let enckey = RistrettoPoint::random(&mut rng);
            let context = b"context";

            let original_share = SecretShare(Scalar::random(&mut rng));

            let encrypted_share = original_share.encrypt(&deckey, &enckey, context);
            let decrypted_share = encrypted_share.unwrap().decrypt(&deckey, &enckey, context);

            assert_eq!(
                original_share.0,
                decrypted_share.unwrap().0,
                "Decryption must return the original share!"
            );
        }
    }
}
