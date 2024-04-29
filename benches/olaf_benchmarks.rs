use criterion::{criterion_group, criterion_main, Criterion};

mod olaf_benches {
    use super::*;
    use criterion::BenchmarkId;
    use merlin::Transcript;
    use rand_core::OsRng;
    use schnorrkel::olaf::{
        errors::DKGResult,
        identifier::Identifier,
        keys::{GroupPublicKey, GroupPublicKeyShare},
        simplpedpop::{
            round1::{self, PrivateData, PublicData, PublicMessage},
            round2,
            round2::Messages,
            round3, Identifiers, Parameters,
        },
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn generate_parameters(max_signers: u16, min_signers: u16) -> Vec<Parameters> {
        (1..=max_signers).map(|_| Parameters::new(max_signers, min_signers)).collect()
    }

    fn round1(
        participants: u16,
        threshold: u16,
    ) -> (Vec<Parameters>, Vec<PrivateData>, Vec<PublicData>, Vec<BTreeSet<PublicMessage>>) {
        let parameters_list = generate_parameters(participants, threshold);

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

        for i in 0..participants {
            all_public_messages.insert(all_public_messages_vec[i as usize].clone());
        }

        // Iterate through each participant to create a set of messages excluding their own.
        for i in 0..participants as usize {
            let own_message = PublicMessage::new(&participants_round1_public_data[i]);

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
    ) -> (Vec<round2::PublicData>, Vec<Messages>, Vec<Identifiers>, Vec<Identifier>) {
        let mut participants_round2_public_data = Vec::new();
        let mut participants_round2_public_messages = Vec::new();
        let mut participants_set_of_participants = Vec::new();
        let mut identifiers_vec = Vec::new();

        for i in 0..*parameters_list[0].participants() {
            let result = round2::run(
                participants_round1_private_data[i as usize].clone(),
                &participants_round1_public_data[i as usize].clone(),
                participants_round1_public_messages[i as usize].clone(),
                Transcript::new(b"simplpedpop"),
            )
            .expect("Round 2 should complete without errors!");

            participants_round2_public_data.push(result.0.clone());
            participants_round2_public_messages.push(result.1);
            participants_set_of_participants.push(result.0.identifiers().clone());
            identifiers_vec.push(*result.0.identifiers().own_identifier());
        }

        (
            participants_round2_public_data,
            participants_round2_public_messages,
            participants_set_of_participants,
            identifiers_vec,
        )
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
                        != *participants_sets_of_participants[i as usize].own_identifier()
                })
                .map(|(index, msg)| (identifiers_vec[index], msg.clone()))
                .collect::<BTreeMap<Identifier, round2::PublicMessage>>();

            let mut round2_private_messages: Vec<BTreeMap<Identifier, round2::PrivateMessage>> =
                Vec::new();

            for participants in participants_sets_of_participants.iter() {
                let mut messages_for_participant = BTreeMap::new();

                for (i, round_messages) in participants_round2_private_messages.iter().enumerate() {
                    if let Some(message) = round_messages.get(&participants.own_identifier()) {
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

    fn benchmark_simplpedpop(c: &mut Criterion) {
        let mut group = c.benchmark_group("SimplPedPoP");

        group
            .sample_size(10)
            .warm_up_time(std::time::Duration::from_secs(2))
            .measurement_time(std::time::Duration::from_secs(30));

        for &n in [3, 10, 100].iter() {
            let participants = n;
            let threshold = (n * 2 + 2) / 3;
            let parameters_list = generate_parameters(participants, threshold);

            group.bench_function(BenchmarkId::new("round1", participants), |b| {
                b.iter(|| {
                    round1::run(parameters_list[0].clone(), OsRng).unwrap();
                })
            });

            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                participants_round1_public_messages,
            ) = round1(participants, threshold);

            group.bench_function(BenchmarkId::new("round2", participants), |b| {
                b.iter(|| {
                    round2::run(
                        participants_round1_private_data[0].clone(),
                        &participants_round1_public_data[0],
                        participants_round1_public_messages[0].clone(),
                        Transcript::new(b"simplpedpop"),
                    )
                    .unwrap();
                })
            });

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
            );

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
                    identifiers_vec[*index]
                        != *participants_sets_of_participants[0].own_identifier()
                })
                .map(|(index, msg)| (identifiers_vec[index], msg.clone()))
                .collect::<BTreeMap<Identifier, round2::PublicMessage>>();

            let mut round2_private_messages: Vec<BTreeMap<Identifier, round2::PrivateMessage>> =
                Vec::new();

            for participants in participants_sets_of_participants.iter() {
                let mut messages_for_participant = BTreeMap::new();

                for (i, round_messages) in participants_round2_private_messages.iter().enumerate() {
                    if let Some(message) = round_messages.get(&participants.own_identifier()) {
                        messages_for_participant.insert(identifiers_vec[i], message.clone());
                    }
                }

                round2_private_messages.push(messages_for_participant);
            }

            group.bench_function(BenchmarkId::new("round3", participants), |b| {
                b.iter(|| {
                    round3::run(
                        &received_round2_public_messages,
                        &participants_round2_public_data[0],
                        &participants_round1_public_data[0],
                        participants_round1_private_data[0].clone(),
                        &round2_private_messages[0],
                    )
                    .unwrap();
                })
            });
        }

        group.finish();
    }

    criterion_group! {
        name = olaf_benches;
        config = Criterion::default();
        targets =
            benchmark_simplpedpop,
    }
}

criterion_main!(olaf_benches::olaf_benches);
