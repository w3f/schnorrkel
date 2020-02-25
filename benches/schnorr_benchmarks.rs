// -*- mode: rust; -*-
//
// This file is part of schnorrkel
// Copyright (c) 2018 Isis Lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>

#[macro_use]
extern crate criterion;
extern crate schnorrkel;
extern crate rand;
// extern crate sha2;

use criterion::Criterion;

mod schnorr_benches {
    use super::*;
    use schnorrkel::{Keypair, PublicKey, Signature, verify_batch, signing_context}; // SecretKey
    use rand::prelude::*; // ThreadRng,thread_rng

    // TODO: fn sign_mini(c: &mut Criterion)

    fn sign(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate();
        let msg: &[u8] = b"";

		let ctx = signing_context(b"this signature does this thing");
        c.bench_function("Schnorr signing", move |b| {
                         b.iter(| | keypair.sign(ctx.bytes(msg)))
        });
    }

    fn verify(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate();
        let msg: &[u8] = b"";
		let ctx = signing_context(b"this signature does this thing");
        let sig: Signature = keypair.sign(ctx.bytes(msg));
        
        c.bench_function("Schnorr signature verification", move |b| {
                         b.iter(| | keypair.verify(ctx.bytes(msg), &sig))
        });
    }

    fn verify_batch_signatures(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 8] = [4, 8, 16, 32, 64, 96, 128, 256];

        c.bench_function_over_inputs(
            "Schnorr batch signature verification",
            |b, &&size| {
                let mut csprng: ThreadRng = thread_rng();
                let keypairs: Vec<Keypair> = (0..size).map(|_| Keypair::generate()).collect();
                let msg: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
				let ctx = signing_context(b"this signature does this thing");
                let signatures:  Vec<Signature> = keypairs.iter().map(|key| key.sign(ctx.bytes(msg))).collect();
                let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();

                b.iter(|| {
					let transcripts = ::std::iter::once(ctx.bytes(msg)).cycle().take(size);
					verify_batch(transcripts, &signatures[..], &public_keys[..])
				});
            },
            &BATCH_SIZES,
        );
    }

    fn key_generation(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();

        c.bench_function("Schnorr keypair generation", move |b| {
                         b.iter(| | Keypair::generate())
        });
    }

    criterion_group!{
        name = schnorr_benches;
        config = Criterion::default();
        targets =
            sign,
            verify,
            verify_batch_signatures,
            key_generation,
    }
}

criterion_main!(
    schnorr_benches::schnorr_benches,
);
