use criterion::criterion_main;

mod olaf_benches {
    use criterion::{criterion_group, BenchmarkId, Criterion};
    use schnorrkel::olaf::multisig::aggregate;
    use schnorrkel::keys::{PublicKey, Keypair};
    use schnorrkel::olaf::multisig::{SigningPackage, SigningNonces, SigningCommitments};
    use schnorrkel::olaf::simplpedpop::AllMessage;

    fn benchmark_simplpedpop(c: &mut Criterion) {
        let mut group = c.benchmark_group("SimplPedPoP");

        group.sample_size(10);

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

    fn benchmark_multisig(c: &mut Criterion) {
        let mut group = c.benchmark_group("multisig");

        group.sample_size(10);

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
                let (signing_nonces, signing_commitments) = spp_output.1.commit();
                all_signing_nonces.push(signing_nonces);
                all_signing_commitments.push(signing_commitments);
            }

            group.bench_function(BenchmarkId::new("round1", participants), |b| {
                b.iter(|| {
                    spp_outputs[0].1.commit();
                })
            });

            let mut signing_packages: Vec<SigningPackage> = Vec::new();

            let message = b"message";
            let context = b"context";

            group.bench_function(BenchmarkId::new("round2", participants), |b| {
                b.iter(|| {
                    spp_outputs[0]
                        .1
                        .sign(
                            context.to_vec(),
                            message.to_vec(),
                            spp_outputs[0].0.clone().spp_output(),
                            all_signing_commitments.clone(),
                            &all_signing_nonces[0],
                        )
                        .unwrap();
                })
            });

            for (i, spp_output) in spp_outputs.iter().enumerate() {
                let signing_package: SigningPackage = spp_output
                    .1
                    .sign(
                        context.to_vec(),
                        message.to_vec(),
                        spp_output.0.clone().spp_output(),
                        all_signing_commitments.clone(),
                        &all_signing_nonces[i],
                    )
                    .unwrap();

                signing_packages.push(signing_package);
            }

            group.bench_function(BenchmarkId::new("aggregate", participants), |b| {
                b.iter(|| {
                    aggregate(&signing_packages).unwrap();
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
            benchmark_multisig,
    }
}

criterion_main!(olaf_benches::olaf_benches);
