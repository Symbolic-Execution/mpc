use crypto::keccak256;
use crate::error::MpcError;
use types::{Attestation, EnclaveMeasurement, X25519PublicKey};

const LOCAL_ATTESTATION_DOMAIN: &[u8] = b"mpc-local-attestation-v1";

pub trait AttestationVerifier: Send + Sync {
    fn verify(
        &self,
        enclave_pubkey: X25519PublicKey,
        measurement: EnclaveMeasurement,
        attestation: &Attestation,
    ) -> Result<(), MpcError>;
}

#[derive(Clone, Debug, Default)]
pub struct LocalAttestationVerifier;

impl LocalAttestationVerifier {
    pub fn attestation_for_tests(
        enclave_pubkey: X25519PublicKey,
        measurement: EnclaveMeasurement,
    ) -> Attestation {
        Attestation(local_attestation_digest(enclave_pubkey, measurement).to_vec())
    }
}

impl AttestationVerifier for LocalAttestationVerifier {
    fn verify(
        &self,
        enclave_pubkey: X25519PublicKey,
        measurement: EnclaveMeasurement,
        attestation: &Attestation,
    ) -> Result<(), MpcError> {
        let expected = local_attestation_digest(enclave_pubkey, measurement);
        if attestation.0 == expected {
            Ok(())
        } else {
            Err(MpcError::Unprocessable("invalid attestation".to_string()))
        }
    }
}

fn local_attestation_digest(
    enclave_pubkey: X25519PublicKey,
    measurement: EnclaveMeasurement,
) -> [u8; 32] {
    let mut binding = Vec::with_capacity(
        LOCAL_ATTESTATION_DOMAIN.len() + enclave_pubkey.0.len() + measurement.0.len(),
    );
    binding.extend_from_slice(LOCAL_ATTESTATION_DOMAIN);
    binding.extend_from_slice(&enclave_pubkey.0);
    binding.extend_from_slice(&measurement.0);
    keccak256(&binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_attestation_binds_pubkey_and_measurement() {
        let verifier = LocalAttestationVerifier;
        let pubkey = X25519PublicKey([1; 32]);
        let measurement = EnclaveMeasurement([2; 32]);
        let attestation = LocalAttestationVerifier::attestation_for_tests(pubkey, measurement);

        verifier.verify(pubkey, measurement, &attestation).unwrap();
    }

    #[test]
    fn local_attestation_rejects_wrong_measurement() {
        let verifier = LocalAttestationVerifier;
        let pubkey = X25519PublicKey([1; 32]);
        let attestation =
            LocalAttestationVerifier::attestation_for_tests(pubkey, EnclaveMeasurement([2; 32]));

        let error = verifier
            .verify(pubkey, EnclaveMeasurement([3; 32]), &attestation)
            .unwrap_err();

        assert!(matches!(error, MpcError::Unprocessable(_)));
    }

    #[test]
    fn local_attestation_rejects_wrong_public_key() {
        let verifier = LocalAttestationVerifier;
        let measurement = EnclaveMeasurement([2; 32]);
        let attestation =
            LocalAttestationVerifier::attestation_for_tests(X25519PublicKey([1; 32]), measurement);

        let error = verifier
            .verify(X25519PublicKey([3; 32]), measurement, &attestation)
            .unwrap_err();

        assert!(matches!(error, MpcError::Unprocessable(_)));
    }
}
