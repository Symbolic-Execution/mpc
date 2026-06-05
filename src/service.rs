use crate::aad::{AadKind, EnclaveAadV1, ReaderAadV1, SourceAad};
use crate::crypto::{
    attestation_digest, open_system_ciphertext, seal_enclave_ciphertext, seal_reader_ciphertext,
};
use crate::error::MpcError;
use crate::state::AppState;
use types::{
    DomainId, HandleId, KeyId, MpcConfigResponse, PutReaderRequest, PutReaderResponse, ReaderId,
    ToEnclaveRequest, ToEnclaveResponse, ToReaderRequest, ToReaderResponse,
};

pub fn get_config(state: &AppState) -> MpcConfigResponse {
    state.config_response()
}

pub fn put_reader(
    state: &AppState,
    reader_id: ReaderId,
    request: PutReaderRequest,
) -> Result<PutReaderResponse, MpcError> {
    state.register_reader(reader_id, request.reader_pubkey)?;

    Ok(PutReaderResponse { reader_id })
}

pub fn to_reader(state: &AppState, request: ToReaderRequest) -> Result<ToReaderResponse, MpcError> {
    let reader_pubkey = state.reader_pubkey(request.reader_id)?;
    require_active_system_key(state, request.system_ciphertext.key_id)?;

    let opened = open_system_ciphertext(state.keypair(), &request.system_ciphertext)?;
    let source = source_context(&opened.source_aad);
    let Some(source_handle_id) = source.handle_id else {
        return Err(unprocessable(
            "to-reader requires handle-bound system ciphertext",
        ));
    };

    if request.chain_id != source.chain_id {
        return Err(unprocessable("request chain_id does not match source aad"));
    }
    if request.handle_id != source_handle_id {
        return Err(unprocessable("request handle_id does not match source aad"));
    }

    let reader_aad = ReaderAadV1 {
        version: 1,
        kind: AadKind::Reader,
        chain_id: source.chain_id,
        domain_id: source.domain_id,
        request_id: request.request_id,
        handle_id: request.handle_id,
        reader_id: request.reader_id,
        type_tag: source.type_tag,
        key_id: source.key_id,
    };

    Ok(ToReaderResponse {
        ciphertext: seal_reader_ciphertext(
            reader_pubkey,
            source.key_id,
            reader_aad,
            &opened.plaintext,
        )?,
    })
}

pub fn to_enclave(
    state: &AppState,
    request: ToEnclaveRequest,
) -> Result<ToEnclaveResponse, MpcError> {
    require_active_system_key(state, request.system_ciphertext.key_id)?;

    let opened = open_system_ciphertext(state.keypair(), &request.system_ciphertext)?;
    let source = source_context(&opened.source_aad);

    if request.chain_id != source.chain_id {
        return Err(unprocessable("request chain_id does not match source aad"));
    }
    if let Some(source_handle_id) = source.handle_id
        && request.handle_id != source_handle_id
    {
        return Err(unprocessable("request handle_id does not match source aad"));
    }

    state.verify_attestation(
        request.enclave_pubkey,
        request.measurement,
        &request.attestation,
    )?;

    if request.measurement != state.config().approved_enclave_measurement {
        return Err(MpcError::Forbidden(
            "enclave measurement is not approved".to_string(),
        ));
    }

    let enclave_aad = EnclaveAadV1 {
        version: 1,
        kind: AadKind::Enclave,
        chain_id: source.chain_id,
        domain_id: source.domain_id,
        request_id: request.request_id,
        handle_id: request.handle_id,
        type_tag: source.type_tag,
        attestation_digest: attestation_digest(&request.attestation),
        key_id: source.key_id,
    };

    Ok(ToEnclaveResponse {
        ciphertext: seal_enclave_ciphertext(
            request.enclave_pubkey,
            source.key_id,
            enclave_aad,
            &opened.plaintext,
        )?,
    })
}

fn require_active_system_key(state: &AppState, ciphertext_key_id: KeyId) -> Result<(), MpcError> {
    if ciphertext_key_id != state.config().key_id {
        return Err(MpcError::NotFound("system key not found".to_string()));
    }

    Ok(())
}

fn unprocessable(message: impl Into<String>) -> MpcError {
    MpcError::Unprocessable(message.into())
}

struct SourceContext {
    chain_id: u64,
    domain_id: DomainId,
    handle_id: Option<HandleId>,
    type_tag: String,
    key_id: KeyId,
}

fn source_context(source: &SourceAad) -> SourceContext {
    match source {
        SourceAad::SystemInput(source) => SourceContext {
            chain_id: source.chain_id,
            domain_id: source.domain_id,
            handle_id: None,
            type_tag: source.type_tag.clone(),
            key_id: source.key_id,
        },
        SourceAad::SystemHandle(source) => SourceContext {
            chain_id: source.chain_id,
            domain_id: source.domain_id,
            handle_id: Some(source.handle_id),
            type_tag: source.type_tag.clone(),
            key_id: source.key_id,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aad::{
        Aad, AadKind, EnclaveAadV1, ReaderAadV1, SystemHandleAadV1, SystemInputAadV1,
        decode_enclave_aad, decode_reader_aad,
    };
    use crate::attestation::LocalAttestationVerifier;
    use crate::crypto::{
        HpkeKeypair, attestation_digest, encode_plaintext_suint256,
        open_enclave_ciphertext_for_tests, open_reader_ciphertext_for_tests, reader_id,
        seal_system_ciphertext,
    };
    use crate::error::MpcError;
    use crate::state::AppState;
    use types::{
        Address, Attestation, EnclaveMeasurement, HandleId, KeyId, PutReaderRequest, ReaderId,
        RequestId, ToEnclaveRequest, ToReaderRequest,
    };

    fn assert_unprocessable<T>(result: Result<T, MpcError>) {
        assert!(matches!(result, Err(MpcError::Unprocessable(_))));
    }

    fn assert_not_found<T>(result: Result<T, MpcError>) {
        assert!(matches!(result, Err(MpcError::NotFound(_))));
    }

    fn assert_forbidden<T>(result: Result<T, MpcError>) {
        assert!(matches!(result, Err(MpcError::Forbidden(_))));
    }

    fn register_reader_for_tests(state: &AppState) -> HpkeKeypair {
        let reader = HpkeKeypair::from_seed_for_tests([8; 32]);
        let reader_id = reader_id(reader.public_key);
        put_reader(
            state,
            reader_id,
            PutReaderRequest {
                reader_pubkey: reader.public_key,
            },
        )
        .unwrap();
        reader
    }

    fn system_handle_ciphertext(
        state: &AppState,
        handle_id: HandleId,
    ) -> (types::SystemCiphertextV1, Vec<u8>) {
        let plaintext = encode_plaintext_suint256([0x99; 32]).unwrap();
        let aad = Aad::SystemHandle(SystemHandleAadV1 {
            version: 1,
            kind: AadKind::SystemHandle,
            chain_id: state.config().chain_id,
            domain_id: state.config().domain_id,
            handle_id,
            type_tag: "suint256".to_string(),
            key_id: state.config().key_id,
        });
        let ciphertext = seal_system_ciphertext(
            &state.config().hpke_public_key,
            state.config().key_id,
            &aad,
            &plaintext,
        )
        .unwrap();

        (ciphertext, plaintext)
    }

    fn system_input_ciphertext(state: &AppState) -> (types::SystemCiphertextV1, Vec<u8>) {
        let plaintext = encode_plaintext_suint256([0xaa; 32]).unwrap();
        let aad = Aad::SystemInput(SystemInputAadV1 {
            version: 1,
            kind: AadKind::SystemInput,
            chain_id: state.config().chain_id,
            domain_id: state.config().domain_id,
            contract: Address([0x55; 20]),
            type_tag: "suint256".to_string(),
            key_id: state.config().key_id,
        });
        let ciphertext = seal_system_ciphertext(
            &state.config().hpke_public_key,
            state.config().key_id,
            &aad,
            &plaintext,
        )
        .unwrap();

        (ciphertext, plaintext)
    }

    fn to_reader_request(
        state: &AppState,
        reader_id: ReaderId,
        handle_id: HandleId,
    ) -> ToReaderRequest {
        let (system_ciphertext, _) = system_handle_ciphertext(state, handle_id);
        ToReaderRequest {
            request_id: RequestId([0x66; 32]),
            chain_id: state.config().chain_id,
            handle_id,
            reader_id,
            system_ciphertext,
        }
    }

    fn to_enclave_request(
        state: &AppState,
        enclave: &HpkeKeypair,
        measurement: EnclaveMeasurement,
        handle_id: HandleId,
    ) -> ToEnclaveRequest {
        let (system_ciphertext, _) = system_handle_ciphertext(state, handle_id);
        ToEnclaveRequest {
            request_id: RequestId([0x77; 32]),
            chain_id: state.config().chain_id,
            handle_id,
            enclave_pubkey: enclave.public_key,
            measurement,
            attestation: LocalAttestationVerifier::attestation_for_tests(
                enclave.public_key,
                measurement,
            ),
            system_ciphertext,
        }
    }

    #[test]
    fn get_config_returns_state_config_response() {
        let state = AppState::local_deterministic_for_tests();

        assert_eq!(get_config(&state), state.config_response());
    }

    #[test]
    fn put_reader_registers_reader() {
        let state = AppState::local_deterministic_for_tests();
        let reader = HpkeKeypair::from_seed_for_tests([8; 32]);
        let id = reader_id(reader.public_key);

        let response = put_reader(
            &state,
            id,
            PutReaderRequest {
                reader_pubkey: reader.public_key,
            },
        )
        .unwrap();

        assert_eq!(response.reader_id, id);
        assert_eq!(state.reader_pubkey(id).unwrap(), reader.public_key);
    }

    #[test]
    fn to_reader_reencrypts_handle_bound_system_ciphertext() {
        let state = AppState::local_deterministic_for_tests();
        let reader = register_reader_for_tests(&state);
        let reader_id = reader_id(reader.public_key);
        let request_id = RequestId([0x66; 32]);
        let handle_id = HandleId([0x44; 32]);
        let (system_ciphertext, plaintext) = system_handle_ciphertext(&state, handle_id);

        let response = to_reader(
            &state,
            ToReaderRequest {
                request_id,
                chain_id: state.config().chain_id,
                handle_id,
                reader_id,
                system_ciphertext,
            },
        )
        .unwrap();

        assert_eq!(
            open_reader_ciphertext_for_tests(&reader, &response.ciphertext).unwrap(),
            plaintext
        );
        assert_eq!(
            decode_reader_aad(&response.ciphertext.aad.0).unwrap(),
            ReaderAadV1 {
                version: 1,
                kind: AadKind::Reader,
                chain_id: state.config().chain_id,
                domain_id: state.config().domain_id,
                request_id,
                handle_id,
                reader_id,
                type_tag: "suint256".to_string(),
                key_id: state.config().key_id,
            }
        );
    }

    #[test]
    fn to_reader_rejects_wrong_handle_id() {
        let state = AppState::local_deterministic_for_tests();
        let reader = register_reader_for_tests(&state);
        let mut request =
            to_reader_request(&state, reader_id(reader.public_key), HandleId([0x44; 32]));
        request.handle_id = HandleId([0x45; 32]);

        assert_unprocessable(to_reader(&state, request));
    }

    #[test]
    fn to_reader_rejects_wrong_chain_id() {
        let state = AppState::local_deterministic_for_tests();
        let reader = register_reader_for_tests(&state);
        let mut request =
            to_reader_request(&state, reader_id(reader.public_key), HandleId([0x44; 32]));
        request.chain_id += 1;

        assert_unprocessable(to_reader(&state, request));
    }

    #[test]
    fn to_reader_rejects_unknown_reader() {
        let state = AppState::local_deterministic_for_tests();
        let request = to_reader_request(&state, ReaderId([0x88; 32]), HandleId([0x44; 32]));

        assert_not_found(to_reader(&state, request));
    }

    #[test]
    fn to_reader_rejects_wrong_system_top_level_key_id() {
        let state = AppState::local_deterministic_for_tests();
        let reader = register_reader_for_tests(&state);
        let mut request =
            to_reader_request(&state, reader_id(reader.public_key), HandleId([0x44; 32]));
        request.system_ciphertext.key_id = KeyId([0x23; 32]);

        assert_not_found(to_reader(&state, request));
    }

    #[test]
    fn to_reader_rejects_system_input_source_aad() {
        let state = AppState::local_deterministic_for_tests();
        let reader = register_reader_for_tests(&state);
        let (system_ciphertext, _) = system_input_ciphertext(&state);

        assert_unprocessable(to_reader(
            &state,
            ToReaderRequest {
                request_id: RequestId([0x66; 32]),
                chain_id: state.config().chain_id,
                handle_id: HandleId([0x44; 32]),
                reader_id: reader_id(reader.public_key),
                system_ciphertext,
            },
        ));
    }

    #[test]
    fn to_enclave_reencrypts_attested_system_ciphertext() {
        let state = AppState::local_deterministic_for_tests();
        let enclave = HpkeKeypair::from_seed_for_tests([10; 32]);
        let measurement = state.config().approved_enclave_measurement;
        let request_id = RequestId([0x77; 32]);
        let handle_id = HandleId([0x44; 32]);
        let attestation =
            LocalAttestationVerifier::attestation_for_tests(enclave.public_key, measurement);
        let (system_ciphertext, plaintext) = system_handle_ciphertext(&state, handle_id);

        let response = to_enclave(
            &state,
            ToEnclaveRequest {
                request_id,
                chain_id: state.config().chain_id,
                handle_id,
                enclave_pubkey: enclave.public_key,
                measurement,
                attestation: attestation.clone(),
                system_ciphertext,
            },
        )
        .unwrap();

        assert_eq!(
            open_enclave_ciphertext_for_tests(&enclave, &response.ciphertext).unwrap(),
            plaintext
        );
        assert_eq!(
            decode_enclave_aad(&response.ciphertext.aad.0).unwrap(),
            EnclaveAadV1 {
                version: 1,
                kind: AadKind::Enclave,
                chain_id: state.config().chain_id,
                domain_id: state.config().domain_id,
                request_id,
                handle_id,
                type_tag: "suint256".to_string(),
                attestation_digest: attestation_digest(&attestation),
                key_id: state.config().key_id,
            }
        );
    }

    #[test]
    fn to_enclave_reencrypts_system_input_ciphertext() {
        let state = AppState::local_deterministic_for_tests();
        let enclave = HpkeKeypair::from_seed_for_tests([10; 32]);
        let measurement = state.config().approved_enclave_measurement;
        let (system_ciphertext, plaintext) = system_input_ciphertext(&state);

        let response = to_enclave(
            &state,
            ToEnclaveRequest {
                request_id: RequestId([0x77; 32]),
                chain_id: state.config().chain_id,
                handle_id: HandleId([0x44; 32]),
                enclave_pubkey: enclave.public_key,
                measurement,
                attestation: LocalAttestationVerifier::attestation_for_tests(
                    enclave.public_key,
                    measurement,
                ),
                system_ciphertext,
            },
        )
        .unwrap();

        assert_eq!(
            open_enclave_ciphertext_for_tests(&enclave, &response.ciphertext).unwrap(),
            plaintext
        );
    }

    #[test]
    fn to_enclave_rejects_wrong_chain_id() {
        let state = AppState::local_deterministic_for_tests();
        let enclave = HpkeKeypair::from_seed_for_tests([10; 32]);
        let mut request = to_enclave_request(
            &state,
            &enclave,
            state.config().approved_enclave_measurement,
            HandleId([0x44; 32]),
        );
        request.chain_id += 1;

        assert_unprocessable(to_enclave(&state, request));
    }

    #[test]
    fn to_enclave_rejects_wrong_handle_id_for_handle_bound_source() {
        let state = AppState::local_deterministic_for_tests();
        let enclave = HpkeKeypair::from_seed_for_tests([10; 32]);
        let mut request = to_enclave_request(
            &state,
            &enclave,
            state.config().approved_enclave_measurement,
            HandleId([0x44; 32]),
        );
        request.handle_id = HandleId([0x45; 32]);

        assert_unprocessable(to_enclave(&state, request));
    }

    #[test]
    fn to_enclave_rejects_invalid_attestation() {
        let state = AppState::local_deterministic_for_tests();
        let enclave = HpkeKeypair::from_seed_for_tests([10; 32]);
        let mut request = to_enclave_request(
            &state,
            &enclave,
            state.config().approved_enclave_measurement,
            HandleId([0x44; 32]),
        );
        request.attestation = Attestation(vec![0xff; 32]);

        assert_unprocessable(to_enclave(&state, request));
    }

    #[test]
    fn to_enclave_rejects_unapproved_measurement_after_valid_attestation() {
        let state = AppState::local_deterministic_for_tests();
        let enclave = HpkeKeypair::from_seed_for_tests([10; 32]);
        let measurement = EnclaveMeasurement([0x34; 32]);
        let request = to_enclave_request(&state, &enclave, measurement, HandleId([0x44; 32]));

        assert_forbidden(to_enclave(&state, request));
    }

    #[test]
    fn to_enclave_rejects_wrong_system_top_level_key_id() {
        let state = AppState::local_deterministic_for_tests();
        let enclave = HpkeKeypair::from_seed_for_tests([10; 32]);
        let mut request = to_enclave_request(
            &state,
            &enclave,
            state.config().approved_enclave_measurement,
            HandleId([0x44; 32]),
        );
        request.system_ciphertext.key_id = KeyId([0x23; 32]);

        assert_not_found(to_enclave(&state, request));
    }
}
