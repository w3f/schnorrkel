use criterion::criterion_main;

mod olaf_benches {
    use rand_core::OsRng;
    use criterion::{criterion_group, BenchmarkId, Criterion};
    use schnorrkel::olaf::frost::aggregate;
    use schnorrkel::keys::{PublicKey, Keypair};
    use schnorrkel::olaf::frost::{SigningNonces, SignatureShare, SigningCommitments};
    use schnorrkel::olaf::simplpedpop::AllMessage;

    fn benchmark_simplpedpop(c: &mut Criterion) {
        let mut group = c.benchmark_group("SimplPedPoP");

        for &n in [3, 10, 100, 1000].iter() {
            let participants = n;
            let threshold = (n * 2 + 2) / 3;

            let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public).collect();

            let mut all_messages: Vec<AllMessage> = Vec::new();

            for i in 0..participants {
                let message = keypairs[i]
                    .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                    .unwrap();
                all_messages.push(message);
            }

            group.bench_function(BenchmarkId::new("round1", participants), |b| {
                b.iter(|| {
                    keypairs[0]
                        .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                        .unwrap();
                })
            });

            group.bench_function(BenchmarkId::new("round2", participants), |b| {
                b.iter(|| {
                    keypairs[0].simplpedpop_recipient_all(&all_messages).unwrap();
                })
            });
        }

        group.finish();
    }

    fn benchmark_frost(c: &mut Criterion) {
        let mut group = c.benchmark_group("FROST");

        for &n in [3, 10, 100, 1000].iter() {
            let participants = n;
            let threshold = (n * 2 + 2) / 3;

            let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public).collect();

            let mut all_messages = Vec::new();
            for i in 0..participants {
                let message = keypairs[i]
                    .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                    .unwrap();
                all_messages.push(message);
            }

            let mut spp_outputs = Vec::new();

            for kp in keypairs.iter() {
                let spp_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();
                spp_outputs.push(spp_output);
            }

            let mut all_signing_commitments: Vec<SigningCommitments> = Vec::new();
            let mut all_signing_nonces: Vec<SigningNonces> = Vec::new();

            for spp_output in &spp_outputs {
                let (signing_nonces, signing_commitments) = spp_output.1.commit(&mut OsRng);
                all_signing_nonces.push(signing_nonces);
                all_signing_commitments.push(signing_commitments);
            }

            group.bench_function(BenchmarkId::new("round1", participants), |b| {
                b.iter(|| {
                    spp_outputs[0].1.commit(&mut OsRng);
                })
            });

            let mut signature_shares: Vec<SignatureShare> = Vec::new();

            let message = b"message";
            let context = b"context";

            group.bench_function(BenchmarkId::new("round2", participants), |b| {
                b.iter(|| {
                    spp_outputs[0]
                        .1
                        .sign(
                            context,
                            message,
                            &spp_outputs[0].0,
                            &all_signing_commitments,
                            &all_signing_nonces[0],
                        )
                        .unwrap();
                })
            });

            for (i, spp_output) in spp_outputs.iter().enumerate() {
                let signature_share: SignatureShare = spp_output
                    .1
                    .sign(
                        context,
                        message,
                        &spp_output.0,
                        &all_signing_commitments,
                        &all_signing_nonces[i],
                    )
                    .unwrap();

                signature_shares.push(signature_share);
            }

            group.bench_function(BenchmarkId::new("aggregate", participants), |b| {
                b.iter(|| {
                    aggregate(
                        message,
                        context,
                        &all_signing_commitments,
                        &signature_shares,
                        spp_outputs[0].0.threshold_public_key(),
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
            benchmark_frost,
    }
}

criterion_main!(olaf_benches::olaf_benches);
