use crate::attestation::{AttestationVerifier, LocalAttestationVerifier};
use crate::error::MpcError;
use crypto::HpkeKeypair;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use types::{
    Attestation, CiphertextSuite, DomainId, EnclaveMeasurement, KeyId, MpcConfigResponse, ReaderId,
    ReaderKeyAlgorithm, X25519PublicKey,
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

pub struct AppStateInner {
    pub config: MpcConfig,
    pub keypair: HpkeKeypair,
    pub readers: RwLock<HashMap<ReaderId, X25519PublicKey>>,
    pub attestation_verifier: Arc<dyn AttestationVerifier>,
}

#[derive(Clone, Debug)]
pub struct MpcConfig {
    pub version: u16,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub key_id: KeyId,
    pub hpke_public_key: X25519PublicKey,
    pub approved_enclave_measurement: EnclaveMeasurement,
}

impl AppState {
    pub fn local_ephemeral() -> Self {
        Self::local_with_keypair(HpkeKeypair::generate())
    }

    pub fn local_deterministic_for_tests() -> Self {
        Self::local_with_keypair(HpkeKeypair::from_seed_for_tests([7; 32]))
    }

    pub fn config_response(&self) -> MpcConfigResponse {
        let config = self.config();
        MpcConfigResponse {
            version: config.version,
            chain_id: config.chain_id,
            domain_id: config.domain_id,
            key_id: config.key_id,
            hpke_public_key: config.hpke_public_key,
            reader_key_algorithm: ReaderKeyAlgorithm::X25519,
            ciphertext_suite: CiphertextSuite::HpkeX25519HkdfSha256Aes256Gcm,
            approved_enclave_measurement: config.approved_enclave_measurement,
        }
    }

    pub fn register_reader(
        &self,
        reader_id: ReaderId,
        pubkey: X25519PublicKey,
    ) -> Result<(), MpcError> {
        if reader_id != crypto::reader_id(pubkey) {
            return Err(MpcError::Conflict(
                "reader_id does not match reader_pubkey".to_string(),
            ));
        }

        let mut readers = self
            .inner
            .readers
            .write()
            .map_err(|_| MpcError::Unavailable("reader registry lock poisoned".to_string()))?;

        if let Some(existing_pubkey) = readers.get(&reader_id) {
            if *existing_pubkey == pubkey {
                return Ok(());
            }

            return Err(MpcError::Conflict(
                "reader_id already registered with different reader_pubkey".to_string(),
            ));
        }

        readers.insert(reader_id, pubkey);
        Ok(())
    }

    pub fn reader_pubkey(&self, reader_id: ReaderId) -> Result<X25519PublicKey, MpcError> {
        let readers = self
            .inner
            .readers
            .read()
            .map_err(|_| MpcError::Unavailable("reader registry lock poisoned".to_string()))?;

        readers
            .get(&reader_id)
            .copied()
            .ok_or_else(|| MpcError::NotFound("reader not found".to_string()))
    }

    pub fn keypair(&self) -> &HpkeKeypair {
        &self.inner.keypair
    }

    pub fn config(&self) -> &MpcConfig {
        &self.inner.config
    }

    pub fn verify_attestation(
        &self,
        pubkey: X25519PublicKey,
        measurement: EnclaveMeasurement,
        attestation: &Attestation,
    ) -> Result<(), MpcError> {
        self.inner
            .attestation_verifier
            .verify(pubkey, measurement, attestation)
    }

    fn local_with_keypair(keypair: HpkeKeypair) -> Self {
        let config = MpcConfig {
            version: 1,
            chain_id: 31337,
            domain_id: DomainId([0x11; 32]),
            key_id: KeyId([0x22; 32]),
            hpke_public_key: keypair.public_key,
            approved_enclave_measurement: EnclaveMeasurement([0x33; 32]),
        };

        Self {
            inner: Arc::new(AppStateInner {
                config,
                keypair,
                readers: RwLock::new(HashMap::new()),
                attestation_verifier: Arc::new(LocalAttestationVerifier),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::reader_id;

    #[test]
    fn reader_registration_is_idempotent() {
        let state = AppState::local_deterministic_for_tests();
        let pubkey = X25519PublicKey([8; 32]);
        let id = reader_id(pubkey);

        state.register_reader(id, pubkey).unwrap();
        state.register_reader(id, pubkey).unwrap();

        assert_eq!(state.reader_pubkey(id).unwrap(), pubkey);
    }

    #[test]
    fn reader_registration_rejects_reader_id_mismatch() {
        let state = AppState::local_deterministic_for_tests();
        let error = state
            .register_reader(
                reader_id(X25519PublicKey([8; 32])),
                X25519PublicKey([9; 32]),
            )
            .unwrap_err();

        assert!(matches!(error, MpcError::Conflict(_)));
    }

    #[test]
    fn reader_registration_rejects_changed_public_key() {
        let state = AppState::local_deterministic_for_tests();
        let pubkey = X25519PublicKey([8; 32]);
        let id = reader_id(pubkey);
        state.register_reader(id, pubkey).unwrap();

        let error = state
            .register_reader(id, X25519PublicKey([9; 32]))
            .unwrap_err();

        assert!(matches!(error, MpcError::Conflict(_)));
    }

    #[test]
    fn unknown_reader_lookup_returns_not_found() {
        let state = AppState::local_deterministic_for_tests();
        let error = state
            .reader_pubkey(reader_id(X25519PublicKey([8; 32])))
            .unwrap_err();

        assert!(matches!(error, MpcError::NotFound(_)));
    }

    #[test]
    fn reader_lookup_returns_unavailable_when_lock_is_poisoned() {
        let state = AppState::local_deterministic_for_tests();
        let state_for_thread = state.clone();

        let _ = std::thread::spawn(move || {
            let _guard = state_for_thread.inner.readers.write().unwrap();
            panic!("poison reader registry lock");
        })
        .join();

        let error = state
            .reader_pubkey(reader_id(X25519PublicKey([8; 32])))
            .unwrap_err();

        assert!(matches!(error, MpcError::Unavailable(_)));
    }

    #[test]
    fn config_response_uses_expected_algorithms() {
        let state = AppState::local_deterministic_for_tests();
        let response = state.config_response();

        assert_eq!(response.reader_key_algorithm, ReaderKeyAlgorithm::X25519);
        assert_eq!(
            response.ciphertext_suite,
            CiphertextSuite::HpkeX25519HkdfSha256Aes256Gcm
        );
    }
}
