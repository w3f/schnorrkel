#[cfg(test)]
mod tests {
    use crate::{
        olaf::{
            frost::{
                aggregate,
                data_structures::{
                    KeyPackage, PublicKeyPackage, SignatureShare, SigningCommitments,
                    SigningNonces, SigningPackage,
                },
                errors::FROSTError,
                verify_signature, Identifier,
            },
            GroupPublicKey,
        },
        Keypair, Signature,
    };
    use alloc::{collections::BTreeMap, vec::Vec};
    use rand_core::{CryptoRng, RngCore};

    /// Test FROST signing with the given shares.
    fn check_sign<R: RngCore + CryptoRng>(
        min_signers: u16,
        key_packages: BTreeMap<Identifier, KeyPackage>,
        mut rng: R,
        pubkey_package: PublicKeyPackage,
    ) -> Result<(Vec<u8>, Signature, GroupPublicKey), FROSTError> {
        let mut nonces_map: BTreeMap<Identifier, SigningNonces> = BTreeMap::new();
        let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

        ////////////////////////////////////////////////////////////////////////////
        // Round 1: generating nonces and signing commitments for each participant
        ////////////////////////////////////////////////////////////////////////////

        for participant_identifier in key_packages.keys().take(min_signers as usize).cloned() {
            // Generate one (1) nonce and one SigningCommitments instance for each
            // participant, up to _min_signers_.
            let sk = key_packages.get(&participant_identifier).unwrap().signing_share.clone();
            let keypair = Keypair::from(sk);

            let (nonces, commitments) = keypair.commit();
            nonces_map.insert(participant_identifier, nonces);
            commitments_map.insert(participant_identifier, commitments);
        }

        // This is what the signature aggregator / coordinator needs to do:
        // - decide what message to sign
        // - take one (unused) commitment per signing participant
        let mut signature_shares = BTreeMap::new();
        let message = b"message to sign";
        let signing_package = SigningPackage::new(commitments_map, message);

        ////////////////////////////////////////////////////////////////////////////
        // Round 2: each participant generates their signature share
        ////////////////////////////////////////////////////////////////////////////

        for participant_identifier in nonces_map.keys() {
            let key_package = key_packages.get(participant_identifier).unwrap();

            let nonces_to_use = nonces_map.get(participant_identifier).unwrap();

            check_sign_errors(signing_package.clone(), nonces_to_use.clone(), key_package.clone());

            let sk = key_package.signing_share.clone();
            let keypair = Keypair::from(sk);

            // Each participant generates their signature share.
            let signature_share = keypair.sign_frost(
                &signing_package,
                nonces_to_use,
                key_package.verifying_key,
                key_package.identifier,
                key_package.min_signers,
            )?;
            signature_shares.insert(*participant_identifier, signature_share);
        }

        ////////////////////////////////////////////////////////////////////////////
        // Aggregation: collects the signing shares from all participants,
        // generates the final signature.
        ////////////////////////////////////////////////////////////////////////////

        #[cfg(not(feature = "cheater-detection"))]
        let pubkey_package = PublicKeyPackage {
            verifying_shares: BTreeMap::new(),
            verifying_key: pubkey_package.verifying_key,
        };

        check_aggregate_errors(
            signing_package.clone(),
            signature_shares.clone(),
            pubkey_package.clone(),
        );

        // Aggregate (also verifies the signature shares)
        let group_signature = aggregate(&signing_package, &signature_shares, &pubkey_package)?;

        // Check that the threshold signature can be verified by the group public
        // key (the verification key).
        verify_signature(b"message to sign", &group_signature, &pubkey_package.verifying_key)?;

        // Check that the threshold signature can be verified by the group public
        // key (the verification key) from KeyPackage.group_public_key
        for (participant_identifier, _) in nonces_map.clone() {
            let key_package = key_packages.get(&participant_identifier).unwrap();

            verify_signature(b"message to sign", &group_signature, &key_package.verifying_key)?;
        }

        Ok((message.to_vec(), group_signature, pubkey_package.verifying_key))
    }

    /// Test FROST signing with the given shares.
    fn check_sign_preprocessing<R: RngCore + CryptoRng>(
        min_signers: u16,
        key_packages: BTreeMap<Identifier, KeyPackage>,
        mut rng: R,
        pubkey_package: PublicKeyPackage,
        num_nonces: u8,
    ) -> Result<(Vec<Vec<u8>>, Vec<Signature>, GroupPublicKey), FROSTError> {
        let mut nonces_map_vec: Vec<BTreeMap<Identifier, SigningNonces>> = Vec::new();
        let mut commitments_map_vec: Vec<BTreeMap<Identifier, SigningCommitments>> = Vec::new();

        ////////////////////////////////////////////////////////////////////////////
        // Round 1: Generating nonces and signing commitments for each participant
        ////////////////////////////////////////////////////////////////////////////

        // First, iterate to gather all nonces and commitments
        let mut all_nonces_map: BTreeMap<Identifier, Vec<SigningNonces>> = BTreeMap::new();
        let mut all_commitments_map: BTreeMap<Identifier, Vec<SigningCommitments>> =
            BTreeMap::new();

        for participant_identifier in key_packages.keys().take(min_signers as usize) {
            let signing_share =
                key_packages.get(&participant_identifier).unwrap().signing_share.clone();
            let keypair = Keypair::from(signing_share);
            let (nonces, commitments) = keypair.preprocess(num_nonces);

            all_nonces_map.insert(participant_identifier.clone(), nonces);
            all_commitments_map.insert(*participant_identifier, commitments);
        }

        // Now distribute these nonces and commitments to individual participant maps
        let mut nonces_map: BTreeMap<Identifier, SigningNonces> = BTreeMap::new();
        let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

        for (id, nonces) in &all_nonces_map {
            for nonce in nonces {
                nonces_map.insert(id.clone(), nonce.clone());
            }
        }

        for (id, commitments) in &all_commitments_map {
            for commitment in commitments {
                commitments_map.insert(id.clone(), commitment.clone());
            }
        }

        nonces_map_vec.push(nonces_map);
        commitments_map_vec.push(commitments_map);

        // This is what the signature aggregator / coordinator needs to do:
        // - decide what message to sign
        // - take one (unused) commitment per signing participant
        let mut signature_shares = BTreeMap::new();

        let mut messages = Vec::new();

        for i in 0..num_nonces {
            let mut message = b"message to sign".to_vec();
            message.extend_from_slice(&i.to_be_bytes());
            messages.push(message);
        }

        ////////////////////////////////////////////////////////////////////////////
        // Round 2: each participant generates their signature share
        ////////////////////////////////////////////////////////////////////////////

        let mut signing_packages = Vec::new();
        let mut group_signatures = Vec::new();

        for i in 0..commitments_map_vec.len() {
            let message = &messages[i as usize];

            let signing_package =
                SigningPackage::new(commitments_map_vec[i as usize].clone(), message);

            signing_packages.push(signing_package.clone());

            for participant_identifier in nonces_map_vec[i as usize].keys() {
                let key_package = key_packages.get(participant_identifier).unwrap();

                let nonces_to_use = nonces_map_vec[i as usize].get(participant_identifier).unwrap();

                check_sign_errors(
                    signing_package.clone(),
                    nonces_to_use.clone(),
                    key_package.clone(),
                );

                let sk = key_package.signing_share.clone();
                let keypair = Keypair::from(sk);

                // Each participant generates their signature share.
                let signature_share = keypair.sign_frost(
                    &signing_package,
                    nonces_to_use,
                    key_package.verifying_key,
                    key_package.identifier,
                    key_package.min_signers,
                )?;
                signature_shares.insert(*participant_identifier, signature_share);
            }

            ////////////////////////////////////////////////////////////////////////////
            // Aggregation: collects the signing shares from all participants,
            // generates the final signature.
            ////////////////////////////////////////////////////////////////////////////

            #[cfg(not(feature = "cheater-detection"))]
            let pubkey_package = PublicKeyPackage {
                verifying_shares: BTreeMap::new(),
                verifying_key: pubkey_package.verifying_key,
            };

            check_aggregate_errors(
                signing_package.clone(),
                signature_shares.clone(),
                pubkey_package.clone(),
            );

            // Aggregate (also verifies the signature shares)
            let group_signature = aggregate(&signing_package, &signature_shares, &pubkey_package)?;

            group_signatures.push(group_signature);

            // Check that the threshold signature can be verified by the group public key.
            verify_signature(message, &group_signature, &pubkey_package.verifying_key)?;

            // Check that the threshold signature can be verified by the group public
            // key from KeyPackage.group_public_key
            for (participant_identifier, _) in nonces_map_vec[i as usize].clone() {
                let key_package = key_packages.get(&participant_identifier).unwrap();

                verify_signature(message, &group_signature, &key_package.verifying_key)?;
            }
        }

        Ok((messages, group_signatures, pubkey_package.verifying_key))
    }

    fn check_sign_errors(
        signing_package: SigningPackage,
        signing_nonces: SigningNonces,
        key_package: KeyPackage,
    ) {
        // Check if passing not enough commitments causes an error

        let mut commitments = signing_package.signing_commitments.clone();
        // Remove one commitment that's not from the key_package owner
        let id = *commitments.keys().find(|&&id| id != key_package.identifier).unwrap();
        commitments.remove(&id);
        let signing_package = SigningPackage::new(commitments, &signing_package.message);

        let sk = key_package.signing_share.clone();
        let keypair = Keypair::from(sk);

        let r = keypair.sign_frost(
            &signing_package,
            &signing_nonces,
            key_package.verifying_key,
            key_package.identifier,
            key_package.min_signers,
        );

        assert_eq!(r, Err(FROSTError::IncorrectNumberOfSigningCommitments));
    }

    fn check_aggregate_errors(
        signing_package: SigningPackage,
        signature_shares: BTreeMap<Identifier, SignatureShare>,
        pubkey_package: PublicKeyPackage,
    ) {
        #[cfg(feature = "cheater-detection")]
        check_aggregate_corrupted_share(
            signing_package.clone(),
            signature_shares.clone(),
            pubkey_package.clone(),
        );

        check_aggregate_invalid_share_identifier_for_verifying_shares(
            signing_package,
            signature_shares,
            pubkey_package,
        );
    }

    #[cfg(feature = "cheater-detection")]
    fn check_aggregate_corrupted_share(
        signing_package: SigningPackage,
        mut signature_shares: BTreeMap<Identifier, SignatureShare>,
        pubkey_package: PublicKeyPackage,
    ) {
        let one = Scalar::ONE;
        // Corrupt a share
        let id = *signature_shares.keys().next().unwrap();
        signature_shares.get_mut(&id).unwrap().share = signature_shares[&id].share + one;
        let e = aggregate(&signing_package, &signature_shares, &pubkey_package).unwrap_err();
        assert_eq!(e, FROSTError::InvalidSignatureShare { culprit: id });
    }

    /// Test NCC-E008263-4VP audit finding (PublicKeyPackage).
    /// Note that the SigningPackage part of the finding is not currently reachable
    /// since it's caught by `compute_lagrange_coefficient()`, and the Binding Factor
    /// part can't either since it's caught before by the PublicKeyPackage part.
    fn check_aggregate_invalid_share_identifier_for_verifying_shares(
        signing_package: SigningPackage,
        mut signature_shares: BTreeMap<Identifier, SignatureShare>,
        pubkey_package: PublicKeyPackage,
    ) {
        // Insert a new share (copied from other existing share) with an invalid identifier
        signature_shares.insert(0, signature_shares.values().next().unwrap().clone());
        // Should error, but not panic
        aggregate(&signing_package, &signature_shares, &pubkey_package)
            .expect_err("should not work");
    }

    #[test]
    fn test_n_of_n_frost_with_simplpedpop() {}
}
