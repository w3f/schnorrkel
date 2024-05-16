//! Errors of the FROST protocol.

use crate::SignatureError;

/// A result for the SimplPedPoP protocol.
pub type FROSTResult<T> = Result<T, FROSTError>;

/// An error ocurred during the execution of the SimplPedPoP protocol.
#[derive(Debug)]
pub enum FROSTError {
    /// Invalid Proof of Possession.
    InvalidProofOfPossession(SignatureError),
    /// The number of signing commitments must be at least equal to the threshold.
    InvalidNumberOfSigningCommitments,
    /// The number of signing commitments must be equal to the number of signature shares.
    IncorrectNumberOfSigningCommitments,
    /// The participant's signing commitment is missing.
    MissingOwnSigningCommitment,
    /// Commitment equals the identity
    IdentitySigningCommitment,
    /// The number of veriyfing shares must be equal to the number of participants.
    IncorrectNumberOfVerifyingShares,
    /// The identifiers of the SimplPedPoP protocol must be the same of the FROST protocol.
    InvalidIdentifier,
    /// The output of the SimplPedPoP protocol must contain the participant's verifying share.
    InvalidOwnVerifyingShare,
    /// Invalid signature.
    InvalidSignature(SignatureError),
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use curve25519_dalek::{traits::Identity, RistrettoPoint};
    use rand_core::OsRng;
    use crate::{
        olaf::{
            frost::types::{NonceCommitment, SigningCommitments},
            simplpedpop::{AllMessage, Parameters},
            SigningKeypair,
        },
        Keypair, PublicKey,
    };
    use super::FROSTError;

    #[test]
    fn test_invalid_own_verifying_share_error() {
        let parameters = Parameters::generate(2, 2);
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
            let (signing_nonces, signing_commitments) = spp_output.1.commit(&mut OsRng);
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";
        let context = b"context";

        spp_outputs[0].1 = SigningKeypair(Keypair::generate());

        let result = spp_outputs[0].1.sign(
            context,
            message,
            &spp_outputs[0].0.spp_output,
            &all_signing_commitments,
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                FROSTError::InvalidOwnVerifyingShare => assert!(true),
                _ => {
                    panic!("Expected FROSTError::InvalidOwnVerifyingShare, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_incorrect_number_of_verifying_shares_error() {
        let parameters = Parameters::generate(2, 2);
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
            let (signing_nonces, signing_commitments) = spp_output.1.commit(&mut OsRng);
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";
        let context = b"context";

        spp_outputs[0].0.spp_output.verifying_keys.pop();

        let result = spp_outputs[0].1.sign(
            context,
            message,
            &spp_outputs[0].0.spp_output,
            &all_signing_commitments,
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                FROSTError::IncorrectNumberOfVerifyingShares => assert!(true),
                _ => {
                    panic!("Expected FROSTError::IncorrectNumberOfVerifyingShares, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_missing_own_signing_commitment_error() {
        let parameters = Parameters::generate(2, 2);
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
            let (signing_nonces, signing_commitments) = spp_output.1.commit(&mut OsRng);
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
            context,
            message,
            &spp_outputs[0].0.spp_output,
            &all_signing_commitments,
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                FROSTError::MissingOwnSigningCommitment => assert!(true),
                _ => {
                    panic!("Expected FROSTError::MissingOwnSigningCommitment, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_identity_signing_commitment_error() {
        let parameters = Parameters::generate(2, 2);
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
            let (signing_nonces, signing_commitments) = spp_output.1.commit(&mut OsRng);
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";
        let context = b"context";

        all_signing_commitments[1].hiding = NonceCommitment(RistrettoPoint::identity());
        let result = spp_outputs[0].1.sign(
            context,
            message,
            &spp_outputs[0].0.spp_output,
            &all_signing_commitments,
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                FROSTError::IdentitySigningCommitment => assert!(true),
                _ => {
                    panic!("Expected FROSTError::IdentitySigningCommitment, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_incorrect_number_of_signing_commitments_error() {
        let parameters = Parameters::generate(2, 2);
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
            let (signing_nonces, signing_commitments) = spp_output.1.commit(&mut OsRng);
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";
        let context = b"context";

        let result = spp_outputs[0].1.sign(
            context,
            message,
            &spp_outputs[0].0.spp_output,
            &all_signing_commitments[..1],
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                FROSTError::InvalidNumberOfSigningCommitments => assert!(true),
                _ => {
                    panic!(
                        "Expected FROSTError::IncorrectNumberOfSigningCommitments, but got {:?}",
                        e
                    )
                },
            },
        }
    }
}
