use criterion::criterion_main;

mod olaf_benches {
    use criterion::{criterion_group, BenchmarkId, Criterion};
    use schnorrkel::keys::{PublicKey, Keypair};
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

    criterion_group! {
        name = olaf_benches;
        config = Criterion::default();
        targets =
            benchmark_simplpedpop,
    }
}

criterion_main!(olaf_benches::olaf_benches);
