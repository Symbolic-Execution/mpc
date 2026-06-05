use ciborium::value::Value;
use std::io::Cursor;
use types::{Address, AttestationDigest, DomainId, HandleId, KeyId, ReaderId, RequestId};

const AAD_VERSION_V1: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("malformed request: {0}")]
    BadRequest(String),
    #[error("invalid request binding: {0}")]
    Unprocessable(String),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AadCodec;

#[derive(Clone, Copy, Debug, Default)]
pub struct PlaintextCodec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AadKind {
    SystemInput = 1,
    SystemHandle = 2,
    Enclave = 3,
    Reader = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemInputAadV1 {
    pub version: u8,
    pub kind: AadKind,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub contract: Address,
    pub type_tag: String,
    pub key_id: KeyId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemHandleAadV1 {
    pub version: u8,
    pub kind: AadKind,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub handle_id: HandleId,
    pub type_tag: String,
    pub key_id: KeyId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclaveAadV1 {
    pub version: u8,
    pub kind: AadKind,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub request_id: RequestId,
    pub handle_id: HandleId,
    pub type_tag: String,
    pub attestation_digest: AttestationDigest,
    pub key_id: KeyId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderAadV1 {
    pub version: u8,
    pub kind: AadKind,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub request_id: RequestId,
    pub handle_id: HandleId,
    pub reader_id: ReaderId,
    pub type_tag: String,
    pub key_id: KeyId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Aad {
    SystemInput(SystemInputAadV1),
    SystemHandle(SystemHandleAadV1),
    Enclave(EnclaveAadV1),
    Reader(ReaderAadV1),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceAad {
    SystemInput(SystemInputAadV1),
    SystemHandle(SystemHandleAadV1),
}

impl AadCodec {
    pub fn encode(aad: &Aad) -> Result<Vec<u8>, CodecError> {
        let (version, kind, expected_kind) = match aad {
            Aad::SystemInput(aad) => (aad.version, aad.kind, AadKind::SystemInput),
            Aad::SystemHandle(aad) => (aad.version, aad.kind, AadKind::SystemHandle),
            Aad::Enclave(aad) => (aad.version, aad.kind, AadKind::Enclave),
            Aad::Reader(aad) => (aad.version, aad.kind, AadKind::Reader),
        };
        if version != AAD_VERSION_V1 {
            return Err(bad_request(format!("unsupported aad version: {version}")));
        }
        if kind != expected_kind {
            return Err(bad_request("aad wrapper kind mismatch"));
        }

        let value = match aad {
            Aad::SystemInput(aad) => Value::Array(vec![
                integer(aad.version),
                integer(aad.kind as u8),
                integer(aad.chain_id),
                bytes(&aad.domain_id.0),
                bytes(&aad.contract.0),
                Value::Text(aad.type_tag.clone()),
                bytes(&aad.key_id.0),
            ]),
            Aad::SystemHandle(aad) => Value::Array(vec![
                integer(aad.version),
                integer(aad.kind as u8),
                integer(aad.chain_id),
                bytes(&aad.domain_id.0),
                bytes(&aad.handle_id.0),
                Value::Text(aad.type_tag.clone()),
                bytes(&aad.key_id.0),
            ]),
            Aad::Enclave(aad) => Value::Array(vec![
                integer(aad.version),
                integer(aad.kind as u8),
                integer(aad.chain_id),
                bytes(&aad.domain_id.0),
                bytes(&aad.request_id.0),
                bytes(&aad.handle_id.0),
                Value::Text(aad.type_tag.clone()),
                bytes(&aad.attestation_digest.0),
                bytes(&aad.key_id.0),
            ]),
            Aad::Reader(aad) => Value::Array(vec![
                integer(aad.version),
                integer(aad.kind as u8),
                integer(aad.chain_id),
                bytes(&aad.domain_id.0),
                bytes(&aad.request_id.0),
                bytes(&aad.handle_id.0),
                bytes(&aad.reader_id.0),
                Value::Text(aad.type_tag.clone()),
                bytes(&aad.key_id.0),
            ]),
        };

        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded)
            .map_err(|err| bad_request(format!("failed to encode aad: {err}")))?;
        Ok(encoded)
    }

    pub fn decode_source(bytes: &[u8]) -> Result<SourceAad, CodecError> {
        let values = decode_array(bytes)?;
        require_version(&values)?;

        match aad_kind(&values)? {
            AadKind::SystemInput => decode_system_input(values).map(SourceAad::SystemInput),
            AadKind::SystemHandle => decode_system_handle(values).map(SourceAad::SystemHandle),
            AadKind::Enclave | AadKind::Reader => Err(bad_request("aad kind is not a source aad")),
        }
    }

    pub fn decode_reader(bytes: &[u8]) -> Result<ReaderAadV1, CodecError> {
        let values = decode_array(bytes)?;
        require_version(&values)?;
        require_kind(&values, AadKind::Reader)?;
        decode_reader(values)
    }

    pub fn decode_enclave(bytes: &[u8]) -> Result<EnclaveAadV1, CodecError> {
        let values = decode_array(bytes)?;
        require_version(&values)?;
        require_kind(&values, AadKind::Enclave)?;
        decode_enclave(values)
    }
}

impl PlaintextCodec {
    pub fn encode_suint256(value: [u8; 32]) -> Result<Vec<u8>, CodecError> {
        Self::encode_bytes(value)
    }

    pub fn encode_sbool(value: bool) -> Result<Vec<u8>, CodecError> {
        Self::encode_bytes([u8::from(value)])
    }

    fn encode_bytes<const N: usize>(bytes: [u8; N]) -> Result<Vec<u8>, CodecError> {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&Value::Bytes(bytes.to_vec()), &mut encoded).map_err(|err| {
            CodecError::Unprocessable(format!("failed to encode plaintext: {err}"))
        })?;
        Ok(encoded)
    }
}

fn decode_system_input(values: Vec<Value>) -> Result<SystemInputAadV1, CodecError> {
    let values = fixed_len::<7>(values)?;
    Ok(SystemInputAadV1 {
        version: read_u8(&values[0], "version")?,
        kind: read_kind(&values[1])?,
        chain_id: read_u64(&values[2], "chain_id")?,
        domain_id: DomainId(read_bytes(&values[3], "domain_id")?),
        contract: Address(read_bytes(&values[4], "contract")?),
        type_tag: read_text(&values[5], "type_tag")?,
        key_id: KeyId(read_bytes(&values[6], "key_id")?),
    })
}

fn decode_system_handle(values: Vec<Value>) -> Result<SystemHandleAadV1, CodecError> {
    let values = fixed_len::<7>(values)?;
    Ok(SystemHandleAadV1 {
        version: read_u8(&values[0], "version")?,
        kind: read_kind(&values[1])?,
        chain_id: read_u64(&values[2], "chain_id")?,
        domain_id: DomainId(read_bytes(&values[3], "domain_id")?),
        handle_id: HandleId(read_bytes(&values[4], "handle_id")?),
        type_tag: read_text(&values[5], "type_tag")?,
        key_id: KeyId(read_bytes(&values[6], "key_id")?),
    })
}

fn decode_enclave(values: Vec<Value>) -> Result<EnclaveAadV1, CodecError> {
    let values = fixed_len::<9>(values)?;
    Ok(EnclaveAadV1 {
        version: read_u8(&values[0], "version")?,
        kind: read_kind(&values[1])?,
        chain_id: read_u64(&values[2], "chain_id")?,
        domain_id: DomainId(read_bytes(&values[3], "domain_id")?),
        request_id: RequestId(read_bytes(&values[4], "request_id")?),
        handle_id: HandleId(read_bytes(&values[5], "handle_id")?),
        type_tag: read_text(&values[6], "type_tag")?,
        attestation_digest: AttestationDigest(read_bytes(&values[7], "attestation_digest")?),
        key_id: KeyId(read_bytes(&values[8], "key_id")?),
    })
}

fn decode_reader(values: Vec<Value>) -> Result<ReaderAadV1, CodecError> {
    let values = fixed_len::<9>(values)?;
    Ok(ReaderAadV1 {
        version: read_u8(&values[0], "version")?,
        kind: read_kind(&values[1])?,
        chain_id: read_u64(&values[2], "chain_id")?,
        domain_id: DomainId(read_bytes(&values[3], "domain_id")?),
        request_id: RequestId(read_bytes(&values[4], "request_id")?),
        handle_id: HandleId(read_bytes(&values[5], "handle_id")?),
        reader_id: ReaderId(read_bytes(&values[6], "reader_id")?),
        type_tag: read_text(&values[7], "type_tag")?,
        key_id: KeyId(read_bytes(&values[8], "key_id")?),
    })
}

fn decode_array(bytes: &[u8]) -> Result<Vec<Value>, CodecError> {
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|err| bad_request(format!("failed to decode aad: {err}")))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(bad_request("aad has trailing data"));
    }

    let mut canonical = Vec::new();
    ciborium::ser::into_writer(&value, &mut canonical)
        .map_err(|err| bad_request(format!("failed to encode canonical aad: {err}")))?;
    if canonical != bytes {
        return Err(bad_request("aad must be canonical cbor"));
    }

    match value {
        Value::Array(values) => Ok(values),
        Value::Map(_) => Err(bad_request("aad must be an array, not a map")),
        _ => Err(bad_request("aad must be an array")),
    }
}

fn require_version(values: &[Value]) -> Result<(), CodecError> {
    let version = values
        .first()
        .ok_or_else(|| bad_request("aad array is missing version"))
        .and_then(|value| read_u8(value, "version"))?;
    if version != AAD_VERSION_V1 {
        return Err(bad_request(format!("unsupported aad version: {version}")));
    }
    Ok(())
}

fn require_kind(values: &[Value], expected: AadKind) -> Result<(), CodecError> {
    let actual = aad_kind(values)?;
    if actual != expected {
        return Err(bad_request("unexpected aad kind"));
    }
    Ok(())
}

fn aad_kind(values: &[Value]) -> Result<AadKind, CodecError> {
    values
        .get(1)
        .ok_or_else(|| bad_request("aad array is missing kind"))
        .and_then(read_kind)
}

fn read_kind(value: &Value) -> Result<AadKind, CodecError> {
    let kind = read_u8(value, "kind")?;

    match kind {
        1 => Ok(AadKind::SystemInput),
        2 => Ok(AadKind::SystemHandle),
        3 => Ok(AadKind::Enclave),
        4 => Ok(AadKind::Reader),
        _ => Err(bad_request(format!("unsupported aad kind: {kind}"))),
    }
}

fn fixed_len<const N: usize>(values: Vec<Value>) -> Result<[Value; N], CodecError> {
    values.try_into().map_err(|values: Vec<Value>| {
        bad_request(format!(
            "expected aad array length {N}, got {}",
            values.len()
        ))
    })
}

fn read_u8(value: &Value, field: &str) -> Result<u8, CodecError> {
    match value {
        Value::Integer(integer) => {
            u8::try_from(*integer).map_err(|_| bad_request(format!("{field} must fit in u8")))
        }
        _ => Err(bad_request(format!("{field} must be an integer"))),
    }
}

fn read_u64(value: &Value, field: &str) -> Result<u64, CodecError> {
    match value {
        Value::Integer(integer) => {
            u64::try_from(*integer).map_err(|_| bad_request(format!("{field} must fit in u64")))
        }
        _ => Err(bad_request(format!("{field} must be an integer"))),
    }
}

fn read_bytes<const N: usize>(value: &Value, field: &str) -> Result<[u8; N], CodecError> {
    match value {
        Value::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| bad_request(format!("{field} must be {N} bytes"))),
        _ => Err(bad_request(format!("{field} must be a byte string"))),
    }
}

fn read_text(value: &Value, field: &str) -> Result<String, CodecError> {
    match value {
        Value::Text(text) => Ok(text.clone()),
        _ => Err(bad_request(format!("{field} must be text"))),
    }
}

fn integer<T>(value: T) -> Value
where
    ciborium::value::Integer: From<T>,
{
    Value::Integer(value.into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn bad_request(message: impl Into<String>) -> CodecError {
    CodecError::BadRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;
    use types::{Address, AttestationDigest, DomainId, HandleId, KeyId, ReaderId, RequestId};

    #[test]
    fn system_input_aad_round_trips_as_fixed_array() {
        let aad = SystemInputAadV1 {
            version: 1,
            kind: AadKind::SystemInput,
            chain_id: 31337,
            domain_id: DomainId([0x11; 32]),
            contract: Address([0x22; 20]),
            type_tag: "suint256".to_string(),
            key_id: KeyId([0x33; 32]),
        };

        let encoded = AadCodec::encode(&Aad::SystemInput(aad.clone())).unwrap();
        assert_eq!(encoded[0], 0x87);
        let decoded = AadCodec::decode_source(&encoded).unwrap();
        assert_eq!(decoded, SourceAad::SystemInput(aad));
    }

    #[test]
    fn system_input_aad_matches_expected_canonical_bytes() {
        let aad = SystemInputAadV1 {
            version: 1,
            kind: AadKind::SystemInput,
            chain_id: 24,
            domain_id: DomainId([0x11; 32]),
            contract: Address([0x22; 20]),
            type_tag: "u8".to_string(),
            key_id: KeyId([0x33; 32]),
        };

        let expected = [
            vec![0x87, 0x01, 0x01, 0x18, 0x18, 0x58, 0x20],
            vec![0x11; 32],
            vec![0x54],
            vec![0x22; 20],
            vec![0x62, b'u', b'8', 0x58, 0x20],
            vec![0x33; 32],
        ]
        .concat();

        let encoded = AadCodec::encode(&Aad::SystemInput(aad)).unwrap();
        assert_eq!(encoded, expected);
    }

    #[test]
    fn system_handle_aad_round_trips_as_fixed_array() {
        let aad = SystemHandleAadV1 {
            version: 1,
            kind: AadKind::SystemHandle,
            chain_id: 31337,
            domain_id: DomainId([0x11; 32]),
            handle_id: HandleId([0x22; 32]),
            type_tag: "suint256".to_string(),
            key_id: KeyId([0x33; 32]),
        };

        let encoded = AadCodec::encode(&Aad::SystemHandle(aad.clone())).unwrap();
        assert_eq!(encoded[0], 0x87);
        let decoded = AadCodec::decode_source(&encoded).unwrap();
        assert_eq!(decoded, SourceAad::SystemHandle(aad));
    }

    #[test]
    fn system_handle_aad_matches_expected_canonical_bytes() {
        let aad = SystemHandleAadV1 {
            version: 1,
            kind: AadKind::SystemHandle,
            chain_id: 24,
            domain_id: DomainId([0x11; 32]),
            handle_id: HandleId([0x22; 32]),
            type_tag: "u8".to_string(),
            key_id: KeyId([0x33; 32]),
        };

        let expected = [
            vec![0x87, 0x01, 0x02, 0x18, 0x18, 0x58, 0x20],
            vec![0x11; 32],
            vec![0x58, 0x20],
            vec![0x22; 32],
            vec![0x62, b'u', b'8', 0x58, 0x20],
            vec![0x33; 32],
        ]
        .concat();

        let encoded = AadCodec::encode(&Aad::SystemHandle(aad)).unwrap();
        assert_eq!(encoded, expected);
    }

    #[test]
    fn enclave_aad_round_trips_as_fixed_array() {
        let aad = EnclaveAadV1 {
            version: 1,
            kind: AadKind::Enclave,
            chain_id: 31337,
            domain_id: DomainId([0x11; 32]),
            request_id: RequestId([0x22; 32]),
            handle_id: HandleId([0x33; 32]),
            type_tag: "suint256".to_string(),
            attestation_digest: AttestationDigest([0x44; 32]),
            key_id: KeyId([0x55; 32]),
        };

        let encoded = AadCodec::encode(&Aad::Enclave(aad.clone())).unwrap();
        assert_eq!(encoded[0], 0x89);
        let decoded = AadCodec::decode_enclave(&encoded).unwrap();
        assert_eq!(decoded, aad);
    }

    #[test]
    fn enclave_aad_matches_expected_canonical_bytes() {
        let aad = EnclaveAadV1 {
            version: 1,
            kind: AadKind::Enclave,
            chain_id: 256,
            domain_id: DomainId([0x11; 32]),
            request_id: RequestId([0x22; 32]),
            handle_id: HandleId([0x33; 32]),
            type_tag: "bool".to_string(),
            attestation_digest: AttestationDigest([0x44; 32]),
            key_id: KeyId([0x55; 32]),
        };

        let expected = [
            vec![0x89, 0x01, 0x03, 0x19, 0x01, 0x00, 0x58, 0x20],
            vec![0x11; 32],
            vec![0x58, 0x20],
            vec![0x22; 32],
            vec![0x58, 0x20],
            vec![0x33; 32],
            vec![0x64, b'b', b'o', b'o', b'l', 0x58, 0x20],
            vec![0x44; 32],
            vec![0x58, 0x20],
            vec![0x55; 32],
        ]
        .concat();

        let encoded = AadCodec::encode(&Aad::Enclave(aad)).unwrap();
        assert_eq!(encoded, expected);
    }

    #[test]
    fn reader_aad_round_trips_as_fixed_array() {
        let aad = ReaderAadV1 {
            version: 1,
            kind: AadKind::Reader,
            chain_id: 31337,
            domain_id: DomainId([0x11; 32]),
            request_id: RequestId([0x22; 32]),
            handle_id: HandleId([0x33; 32]),
            reader_id: ReaderId([0x44; 32]),
            type_tag: "suint256".to_string(),
            key_id: KeyId([0x55; 32]),
        };

        let encoded = AadCodec::encode(&Aad::Reader(aad.clone())).unwrap();
        assert_eq!(encoded[0], 0x89);
        let decoded = AadCodec::decode_reader(&encoded).unwrap();
        assert_eq!(decoded, aad);
    }

    #[test]
    fn reader_aad_matches_expected_canonical_bytes() {
        let aad = ReaderAadV1 {
            version: 1,
            kind: AadKind::Reader,
            chain_id: 256,
            domain_id: DomainId([0x11; 32]),
            request_id: RequestId([0x22; 32]),
            handle_id: HandleId([0x33; 32]),
            reader_id: ReaderId([0x44; 32]),
            type_tag: "bool".to_string(),
            key_id: KeyId([0x55; 32]),
        };

        let expected = [
            vec![0x89, 0x01, 0x04, 0x19, 0x01, 0x00, 0x58, 0x20],
            vec![0x11; 32],
            vec![0x58, 0x20],
            vec![0x22; 32],
            vec![0x58, 0x20],
            vec![0x33; 32],
            vec![0x58, 0x20],
            vec![0x44; 32],
            vec![0x64, b'b', b'o', b'o', b'l', 0x58, 0x20],
            vec![0x55; 32],
        ]
        .concat();

        let encoded = AadCodec::encode(&Aad::Reader(aad)).unwrap();
        assert_eq!(encoded, expected);
    }

    #[test]
    fn decode_rejects_map_encoded_aad() {
        let value = Value::Map(vec![
            (Value::Text("version".to_string()), Value::Integer(1.into())),
            (Value::Text("kind".to_string()), Value::Integer(1.into())),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).unwrap();

        let err = AadCodec::decode_source(&encoded).unwrap_err();
        assert!(matches!(err, CodecError::BadRequest(_)));
    }

    #[test]
    fn decode_rejects_non_canonical_indefinite_array_aad() {
        let non_canonical = [
            vec![0x9f, 0x01, 0x02, 0x18, 0x18, 0x58, 0x20],
            vec![0x11; 32],
            vec![0x58, 0x20],
            vec![0x22; 32],
            vec![0x62, b'u', b'8', 0x58, 0x20],
            vec![0x33; 32],
            vec![0xff],
        ]
        .concat();

        let err = AadCodec::decode_source(&non_canonical).unwrap_err();
        assert!(matches!(err, CodecError::BadRequest(_)));
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let value = system_handle_value_with(
            Value::Integer(2.into()),
            Value::Text("u8".to_string()),
            vec![0x11; 32],
        );
        let encoded = encode_value(&value);

        let err = AadCodec::decode_source(&encoded).unwrap_err();
        assert!(matches!(err, CodecError::BadRequest(_)));
    }

    #[test]
    fn decode_rejects_wrong_array_length() {
        let value = Value::Array(vec![
            Value::Integer(1.into()),
            Value::Integer((AadKind::SystemHandle as u8).into()),
            Value::Integer(24.into()),
        ]);
        let encoded = encode_value(&value);

        let err = AadCodec::decode_source(&encoded).unwrap_err();
        assert!(matches!(err, CodecError::BadRequest(_)));
    }

    #[test]
    fn decode_rejects_wrong_fixed_byte_width() {
        let value = system_handle_value_with(
            Value::Integer(1.into()),
            Value::Text("u8".to_string()),
            vec![0x11; 31],
        );
        let encoded = encode_value(&value);

        let err = AadCodec::decode_source(&encoded).unwrap_err();
        assert!(matches!(err, CodecError::BadRequest(_)));
    }

    #[test]
    fn decode_rejects_non_text_type_tag() {
        let value = system_handle_value_with(
            Value::Integer(1.into()),
            Value::Integer(7.into()),
            vec![0x11; 32],
        );
        let encoded = encode_value(&value);

        let err = AadCodec::decode_source(&encoded).unwrap_err();
        assert!(matches!(err, CodecError::BadRequest(_)));
    }

    #[test]
    fn decode_rejects_trailing_data() {
        let mut encoded = encode_value(&system_handle_value_with(
            Value::Integer(1.into()),
            Value::Text("u8".to_string()),
            vec![0x11; 32],
        ));
        encoded.push(0x00);

        let err = AadCodec::decode_source(&encoded).unwrap_err();
        assert!(matches!(err, CodecError::BadRequest(_)));
    }

    #[test]
    fn encode_rejects_unsupported_version() {
        let aad = SystemInputAadV1 {
            version: 2,
            kind: AadKind::SystemInput,
            chain_id: 31337,
            domain_id: DomainId([0x11; 32]),
            contract: Address([0x22; 20]),
            type_tag: "suint256".to_string(),
            key_id: KeyId([0x33; 32]),
        };

        let err = AadCodec::encode(&Aad::SystemInput(aad)).unwrap_err();
        assert!(matches!(err, CodecError::BadRequest(_)));
    }

    #[test]
    fn encode_rejects_wrapper_struct_kind_mismatch() {
        let aad = SystemHandleAadV1 {
            version: 1,
            kind: AadKind::SystemInput,
            chain_id: 31337,
            domain_id: DomainId([0x11; 32]),
            handle_id: HandleId([0x22; 32]),
            type_tag: "suint256".to_string(),
            key_id: KeyId([0x33; 32]),
        };

        let err = AadCodec::encode(&Aad::SystemHandle(aad)).unwrap_err();
        assert!(matches!(err, CodecError::BadRequest(_)));
    }

    #[test]
    fn decode_rejects_unsupported_kind() {
        let value = Value::Array(vec![
            Value::Integer(1.into()),
            Value::Integer(99.into()),
            Value::Integer(31337.into()),
            Value::Bytes(vec![0x11; 32]),
            Value::Bytes(vec![0x22; 32]),
            Value::Text("suint256".to_string()),
            Value::Bytes(vec![0x33; 32]),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).unwrap();

        let err = AadCodec::decode_source(&encoded).unwrap_err();
        assert!(matches!(err, CodecError::BadRequest(_)));
    }

    #[test]
    fn plaintext_codec_encodes_canonical_cbor_byte_strings() {
        assert_eq!(
            PlaintextCodec::encode_suint256([0x7a; 32]).unwrap(),
            [vec![0x58, 0x20], vec![0x7a; 32]].concat()
        );
        assert_eq!(
            PlaintextCodec::encode_sbool(true).unwrap(),
            vec![0x41, 0x01]
        );
        assert_eq!(
            PlaintextCodec::encode_sbool(false).unwrap(),
            vec![0x41, 0x00]
        );
    }

    fn system_handle_value_with(version: Value, type_tag: Value, domain_id: Vec<u8>) -> Value {
        Value::Array(vec![
            version,
            Value::Integer((AadKind::SystemHandle as u8).into()),
            Value::Integer(24.into()),
            Value::Bytes(domain_id),
            Value::Bytes(vec![0x22; 32]),
            type_tag,
            Value::Bytes(vec![0x33; 32]),
        ])
    }

    fn encode_value(value: &Value) -> Vec<u8> {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(value, &mut encoded).unwrap();
        encoded
    }
}
