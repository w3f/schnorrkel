//! Errors of the two-round threshold multisig protocol.

use core::array::TryFromSliceError;

use alloc::vec::Vec;

use crate::{
    olaf::{simplpedpop::errors::SPPError, VerifyingShare},
    SignatureError,
};

/// A result for the SimplPedPoP protocol.
pub type MultiSigResult<T> = Result<T, MultiSigError>;

/// An error ocurred during the execution of the SimplPedPoP protocol.
#[derive(Debug)]
pub enum MultiSigError {
    /// The number of signing commitments must be at least equal to the threshold.
    InvalidNumberOfSigningCommitments,
    /// The participant's signing commitment is missing.
    MissingOwnSigningCommitment,
    /// Commitment equals the identity
    IdentitySigningCommitment,
    /// The number of veriyfing shares must be equal to the number of signers.
    IncorrectNumberOfVerifyingShares,
    /// Error deserializing the signature share.
    SignatureShareDeserializationError,
    /// The signature share is invalid.
    InvalidSignatureShare {
        /// The verifying share(s) of the culprit(s).
        culprit: Vec<VerifyingShare>,
    },
    /// The output of the SimplPedPoP protocol must contain the participant's verifying share.
    InvalidOwnVerifyingShare,
    /// Invalid signature.
    InvalidSignature(SignatureError),
    /// Deserialization error.
    DeserializationError(TryFromSliceError),
    /// Invalid nonce commitment.
    InvalidNonceCommitment,
    /// Error deserializing the output of the SimplPedPoP protocol.
    SPPOutputDeserializationError(SPPError),
    /// The number of signing packages must be at least equal to the threshold.
    InvalidNumberOfSigningPackages,
    /// The common data of all the signing packages must be the same.
    MismatchedCommonData,
    /// The number of signature shares and the number of signing commitments must be the same.
    MismatchedSignatureSharesAndSigningCommitments,
    /// The signing packages are empty.
    EmptySigningPackages,
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
    use rand_core::OsRng;
    use crate::{
        olaf::{
            multisig::{
                aggregate,
                types::{NonceCommitment, SigningCommitments},
                SigningPackage,
            },
            simplpedpop::AllMessage,
            test_utils::generate_parameters,
            SigningKeypair,
        },
        Keypair, PublicKey,
    };
    use super::MultiSigError;

    #[test]
    fn test_empty_signing_packages() {
        let signing_packages: Vec<SigningPackage> = Vec::new();

        let result = aggregate(&signing_packages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                MultiSigError::EmptySigningPackages => assert!(true),
                _ => {
                    panic!("Expected MultiSigError::EmptySigningPackages, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_invalid_signature_share() {
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
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit();
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let mut signing_packages = Vec::new();

        let message = b"message";
        let context = b"context";

        for (i, spp_output) in spp_outputs.iter().enumerate() {
            let signing_package = spp_output
                .1
                .sign(
                    context.to_vec(),
                    message.to_vec(),
                    spp_output.0.spp_output.clone(),
                    all_signing_commitments.clone(),
                    &all_signing_nonces[i],
                )
                .unwrap();

            signing_packages.push(signing_package);
        }

        signing_packages[0].signer_data.signature_share.share += Scalar::ONE;
        signing_packages[1].signer_data.signature_share.share += Scalar::ONE;

        let result = aggregate(&signing_packages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                MultiSigError::InvalidSignatureShare { culprit } => {
                    assert_eq!(
                        culprit,
                        vec![
                            spp_outputs[0].0.spp_output.verifying_keys[0].1,
                            spp_outputs[0].0.spp_output.verifying_keys[1].1
                        ]
                    );
                },
                _ => panic!("Expected MultiSigError::InvalidSignatureShare, but got {:?}", e),
            },
        }
    }

    #[test]
    fn test_mismatched_signature_shares_and_signing_commitments_error() {
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
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit();
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let mut signing_packages = Vec::new();

        let message = b"message";
        let context = b"context";

        for (i, spp_output) in spp_outputs.iter().enumerate() {
            let mut signing_package = spp_output
                .1
                .sign(
                    context.to_vec(),
                    message.to_vec(),
                    spp_output.0.spp_output.clone(),
                    all_signing_commitments.clone(),
                    &all_signing_nonces[i],
                )
                .unwrap();

            signing_package.common_data.signing_commitments.pop();

            signing_packages.push(signing_package);
        }

        let result = aggregate(&signing_packages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                MultiSigError::MismatchedSignatureSharesAndSigningCommitments => assert!(true),
                _ => {
                    panic!("Expected MultiSigError::MismatchedSignatureSharesAndSigningCommitments, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_mismatched_common_data_error() {
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
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit();
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let mut signing_packages = Vec::new();

        let message = b"message";
        let context = b"context";

        for (i, spp_output) in spp_outputs.iter().enumerate() {
            let signing_package = spp_output
                .1
                .sign(
                    context.to_vec(),
                    message.to_vec(),
                    spp_output.0.spp_output.clone(),
                    all_signing_commitments.clone(),
                    &all_signing_nonces[i],
                )
                .unwrap();

            signing_packages.push(signing_package);
        }

        signing_packages[0].common_data.context = b"invalid_context".to_vec();

        let result = aggregate(&signing_packages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                MultiSigError::MismatchedCommonData => assert!(true),
                _ => {
                    panic!("Expected MultiSigError::MismatchedCommonData, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_invalid_number_of_signing_packages_error() {
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
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit();
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let mut signing_packages = Vec::new();

        let message = b"message";
        let context = b"context";

        let signing_package = spp_outputs[0]
            .1
            .sign(
                context.to_vec(),
                message.to_vec(),
                spp_outputs[0].0.spp_output.clone(),
                all_signing_commitments.clone(),
                &all_signing_nonces[0],
            )
            .unwrap();

        signing_packages.push(signing_package);

        let result = aggregate(&signing_packages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                MultiSigError::InvalidNumberOfSigningPackages => assert!(true),
                _ => {
                    panic!("Expected MultiSigError::InvalidNumberOfSigningPackages, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_invalid_own_verifying_share_error() {
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
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit();
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";
        let context = b"context";

        spp_outputs[0].1 = SigningKeypair(Keypair::generate());

        let result = spp_outputs[0].1.sign(
            context.to_vec(),
            message.to_vec(),
            spp_outputs[0].0.spp_output.clone(),
            all_signing_commitments.clone(),
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                MultiSigError::InvalidOwnVerifyingShare => assert!(true),
                _ => {
                    panic!("Expected MultiSigError::InvalidOwnVerifyingShare, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_incorrect_number_of_verifying_shares_error() {
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
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit();
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";
        let context = b"context";

        spp_outputs[0].0.spp_output.verifying_keys.pop();

        let result = spp_outputs[0].1.sign(
            context.to_vec(),
            message.to_vec(),
            spp_outputs[0].0.spp_output.clone(),
            all_signing_commitments.clone(),
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                MultiSigError::IncorrectNumberOfVerifyingShares => assert!(true),
                _ => {
                    panic!("Expected MultiSigError::IncorrectNumberOfVerifyingShares, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_missing_own_signing_commitment_error() {
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
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit();
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";
        let context = b"context";

        all_signing_commitments[0] = SigningCommitments {
            hiding: NonceCommitment(RistrettoPoint::random(&mut OsRng)),
            binding: NonceCommitment(RistrettoPoint::random(&mut OsRng)),
        };

        let result = spp_outputs[0].1.sign(
            context.to_vec(),
            message.to_vec(),
            spp_outputs[0].0.spp_output.clone(),
            all_signing_commitments.clone(),
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                MultiSigError::MissingOwnSigningCommitment => assert!(true),
                _ => {
                    panic!("Expected MultiSigError::MissingOwnSigningCommitment, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_identity_signing_commitment_error() {
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
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit();
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";
        let context = b"context";

        all_signing_commitments[1].hiding = NonceCommitment(RistrettoPoint::identity());

        let result = spp_outputs[0].1.sign(
            context.to_vec(),
            message.to_vec(),
            spp_outputs[0].0.spp_output.clone(),
            all_signing_commitments.clone(),
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                MultiSigError::IdentitySigningCommitment => assert!(true),
                _ => {
                    panic!("Expected MultiSigError::IdentitySigningCommitment, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_invalid_number_of_signing_commitments_error() {
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
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit();
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";
        let context = b"context";

        let result = spp_outputs[0].1.sign(
            context.to_vec(),
            message.to_vec(),
            spp_outputs[0].0.spp_output.clone(),
            all_signing_commitments
                .into_iter()
                .take(parameters.threshold as usize - 1)
                .collect::<Vec<SigningCommitments>>()
                .clone(),
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                MultiSigError::InvalidNumberOfSigningCommitments => assert!(true),
                _ => {
                    panic!(
                        "Expected MultiSigError::InvalidNumberOfSigningCommitments, but got {:?}",
                        e
                    )
                },
            },
        }
    }
}
