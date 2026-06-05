use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;

pub type Address = FixedBytes<20>;
pub type Bytes32 = FixedBytes<32>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

pub type DomainId = Bytes32;
pub type KeyId = Bytes32;
pub type RequestId = Bytes32;
pub type ReaderId = Bytes32;
pub type HandleId = Bytes32;
pub type EnclaveMeasurement = Bytes32;
pub type AttestationDigest = Bytes32;
pub type X25519PublicKey = FixedBytes<32>;

#[allow(non_snake_case)]
pub fn Address(bytes: [u8; 20]) -> Address {
    FixedBytes(bytes)
}

#[allow(non_snake_case)]
pub fn Bytes32(bytes: [u8; 32]) -> Bytes32 {
    FixedBytes(bytes)
}

#[allow(non_snake_case)]
pub fn DomainId(bytes: [u8; 32]) -> DomainId {
    FixedBytes(bytes)
}

#[allow(non_snake_case)]
pub fn KeyId(bytes: [u8; 32]) -> KeyId {
    FixedBytes(bytes)
}

#[allow(non_snake_case)]
pub fn RequestId(bytes: [u8; 32]) -> RequestId {
    FixedBytes(bytes)
}

#[allow(non_snake_case)]
pub fn ReaderId(bytes: [u8; 32]) -> ReaderId {
    FixedBytes(bytes)
}

#[allow(non_snake_case)]
pub fn HandleId(bytes: [u8; 32]) -> HandleId {
    FixedBytes(bytes)
}

#[allow(non_snake_case)]
pub fn EnclaveMeasurement(bytes: [u8; 32]) -> EnclaveMeasurement {
    FixedBytes(bytes)
}

#[allow(non_snake_case)]
pub fn AttestationDigest(bytes: [u8; 32]) -> AttestationDigest {
    FixedBytes(bytes)
}

#[allow(non_snake_case)]
pub fn X25519PublicKey(bytes: [u8; 32]) -> X25519PublicKey {
    FixedBytes(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadBytes(pub Vec<u8>);

impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut hex = String::with_capacity(2 + (N * 2));
        hex.push_str("0x");
        hex.push_str(&hex::encode(self.0));
        serializer.serialize_str(&hex)
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedBytesVisitor<const N: usize>;

        impl<const N: usize> de::Visitor<'_> for FixedBytesVisitor<N> {
            type Value = FixedBytes<N>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a 0x-prefixed hex string with {N} bytes")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let hex = value
                    .strip_prefix("0x")
                    .ok_or_else(|| E::custom("missing 0x prefix"))?;
                if hex.len() != N * 2 {
                    return Err(E::custom(format!("expected {} hex characters", N * 2)));
                }

                let decoded = hex::decode(hex).map_err(E::custom)?;
                let bytes: [u8; N] = decoded
                    .try_into()
                    .map_err(|_| E::custom(format!("expected {N} bytes")))?;

                Ok(FixedBytes(bytes))
            }
        }

        deserializer.deserialize_str(FixedBytesVisitor::<N>)
    }
}

fn serialize_base64url<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
}

fn deserialize_base64url<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    URL_SAFE_NO_PAD.decode(encoded).map_err(de::Error::custom)
}

impl Serialize for PayloadBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_base64url(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PayloadBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_base64url(deserializer).map(Self)
    }
}

impl Serialize for Attestation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_base64url(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Attestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_base64url(deserializer).map(Self)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ReaderKeyAlgorithm {
    X25519,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum CiphertextSuite {
    HpkeX25519HkdfSha256Aes256Gcm,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct MpcConfigResponse {
    pub version: u16,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub key_id: KeyId,
    pub hpke_public_key: X25519PublicKey,
    pub reader_key_algorithm: ReaderKeyAlgorithm,
    pub ciphertext_suite: CiphertextSuite,
    pub approved_enclave_measurement: EnclaveMeasurement,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PutReaderRequest {
    pub reader_pubkey: X25519PublicKey,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PutReaderResponse {
    pub reader_id: ReaderId,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SystemCiphertextV1 {
    pub key_id: KeyId,
    pub enc: PayloadBytes,
    pub wrapped_key: PayloadBytes,
    pub nonce: FixedBytes<12>,
    pub ciphertext: PayloadBytes,
    pub aad: PayloadBytes,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EnclaveCiphertextV1 {
    pub key_id: KeyId,
    pub enc: PayloadBytes,
    pub ciphertext: PayloadBytes,
    pub aad: PayloadBytes,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ReaderCiphertextV1 {
    pub key_id: KeyId,
    pub enc: PayloadBytes,
    pub ciphertext: PayloadBytes,
    pub aad: PayloadBytes,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ToEnclaveRequest {
    pub request_id: RequestId,
    pub chain_id: u64,
    pub handle_id: HandleId,
    pub enclave_pubkey: X25519PublicKey,
    pub measurement: EnclaveMeasurement,
    pub attestation: Attestation,
    pub system_ciphertext: SystemCiphertextV1,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ToEnclaveResponse {
    pub ciphertext: EnclaveCiphertextV1,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ToReaderRequest {
    pub request_id: RequestId,
    pub chain_id: u64,
    pub handle_id: HandleId,
    pub reader_id: ReaderId,
    pub system_ciphertext: SystemCiphertextV1,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ToReaderResponse {
    pub ciphertext: ReaderCiphertextV1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes32_json_uses_lowercase_0x_hex() {
        let value = Bytes32([0xab; 32]);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(
            json,
            "\"0xabababababababababababababababababababababababababababababababab\""
        );
        let decoded: Bytes32 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn payload_bytes_json_use_base64url_without_padding() {
        let value = PayloadBytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, "\"3q2-7w\"");
        let decoded: PayloadBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, value);
    }
}
