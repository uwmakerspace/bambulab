use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::x509::X509;
use serde_json::{Value, json};
use std::error::Error;

const SIGN_VER: &str = "v1.0";
const SIGN_ALG: &str = "RSA_SHA256";

// Intentionally embedded to match newer firmware signing expectations.
// This should be replaced with runtime-provisioned key material in a future change.
const BAMBUCONNECT_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDQNp2NfkajwcWH
PIqosa08P1ZwETPr1veZCMqieQxWtYw97wp+JCxX4yBrBcAwid7o7PHI9KQVzPRM
f0uXspaDUdSljrfJ/YwGEz7+GJz4+ml1UbWXBePyzXW1+N2hIGGn7BcNuA0v8rMY
uvVgiIIQNjLErgGcCWmMHLwsMMQ7LNprUZZKsSNB4HaQDH7cQZmYBN/O45np6l+K
VuLdzXdDpZcOM7bNO6smev822WPGDuKBo1iVfQbUe10X4dCNwkBR3QGpScVvg8gg
tRYZDYue/qc4Xaj806RZPttknWfxdvfZgoOmAiwnyQ5K3+mzNYHgQZAOC2ydkK4J
s+ZizK3lAgMBAAECggEAKwEcyXyrWmdLRQNcIDuSbD8ouzzSXIOp4BHQyH337nDQ
5nnY0PTns79VksU9TMktIS7PQZJF0brjOmmQU2SvcbAVG5y+mRmlMhwHhrPOuB4A
ahrWRrsQubV1+n/MRttJUEWS/WJmVuDp3NHAnI+VTYPkOHs4GeJXynik5PutjAr3
tYmr3kaw0Wo/hYAXTKsI/R5aenC7jH8ZSyVcZ/j+bOSH5sT5/JY122AYmkQOFE7s
JA0EfYJaJEwiuBWKOfRLQVEHhOFodUBZdGQcWeW3uFb88aYKN8QcKTO8/f6e4r8w
QojgK3QMj1zmfS7xid6XCOVa17ary2hZHAEPnjcigQKBgQDQnm4TlbVTsM+CbFUS
1rOIJRzPdnH3Y7x3IcmVKZt81eNktsdu56A4U6NEkFQqk4tVTT4TYja/hwgXmm6w
J+w0WwZd445Bxj8PmaEr6Z/NSMYbCsi8pRelKWmlIMwD2YhtY/1xXD37zpOgN8oQ
ryTKZR2gljbPxdfhKS7YerLp2wKBgQD/gJt3Ds69j1gMDLnnPctjmhsPRXh7PQ0e
E9lqgFkx/vNuCuyRs6ymic2rBZmkdlpjsTJFmz1bwOzIvSRoH6kp0Mfyo6why5kr
upDf7zz+hlvaFewme8aDeV3ex9Wvt73D66nwAy5ABOgn+66vZJeo0Iq/tnCwK3a/
evTL9BOzPwKBgEUi7AnziEc3Bl4Lttnqa08INZcPgs9grzmv6dVUF6J0Y8qhxFAd
1Pw1w5raVfpSMU/QrGzSFKC+iFECLgKVCHOFYwPEgQWNRKLP4BjkcMAgiP63QTU7
ZS2oHsnJp7Ly6YKPK5Pg5O3JVSU4t+91i7TDc+EfRwTuZQ/KjSrS5u4XAoGBAP06
v9reSDVELuWyb0Yqzrxm7k7ScbjjJ28aCTAvCTguEaKNHS7DP2jHx5mrMT35N1j7
NHIcjFG2AnhqTf0M9CJHlQR9B4tvON5ISHJJsNAq5jpd4/G4V2XTEiBNOxKvL1tQ
5NrGrD4zHs0R+25GarGcDwg3j7RrP4REHv9NZ4ENAoGAY7Nuz6xKu2XUwuZtJP7O
kjsoDS7bjP95ddrtsRq5vcVjJ04avnjsr+Se9WDA//t7+eSeHjm5eXD7u0NtdqZo
WtSm8pmWySOPXMn9QQmdzKHg1NOxer//f1KySVunX1vftTStjsZH7dRCtBEePcqg
z5Av6MmEFDojtwTqvEZuhBM=
-----END PRIVATE KEY-----"#;

const BAMBUCONNECT_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIRAO48rAcSzurNqLf7xC50uiwwDQYJKoZIhvcNAQELBQAw
JjEkMCIGA1UEAwwbR0xPRjM4MTM3MzQwODkuYmFtYnVsYWIuY29tMB4XDTI0MTIx
MTA5MjkyMFoXDTI1MTIxMjA5MjkyMFowTDEkMCIGA1UEChMbR0xPRjM4MTM3MzQw
ODktNTI0YTM3YzgwMDAwMSQwIgYDVQQDExtHTE9GMzgxMzczNDA4OS01MjRhMzdj
ODAwMDAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQNp2NfkajwcWH
PIqosa08P1ZwETPr1veZCMqieQxWtYw97wp+JCxX4yBrBcAwid7o7PHI9KQVzPRM
f0uXspaDUdSljrfJ/YwGEz7+GJz4+ml1UbWXBePyzXW1+N2hIGGn7BcNuA0v8rMY
uvVgiIIQNjLErgGcCWmMHLwsMMQ7LNprUZZKsSNB4HaQDH7cQZmYBN/O45np6l+K
VuLdzXdDpZcOM7bNO6smev822WPGDuKBo1iVfQbUe10X4dCNwkBR3QGpScVvg8gg
tRYZDYue/qc4Xaj806RZPttknWfxdvfZgoOmAiwnyQ5K3+mzNYHgQZAOC2ydkK4J
s+ZizK3lAgMBAAGjYDBeMA4GA1UdDwEB/wQEAwIDuDAMBgNVHRMBAf8EAjAAMB0G
A1UdDgQWBBTbM6dbfGu7o6o1IU59QyDzMcexjzAfBgNVHSMEGDAWgBTCydEtLumS
2pknAxmjOizTHKwImzANBgkqhkiG9w0BAQsFAAOCAQEAmmD3Fu37vgw4qr/Dgr15
FSdoCuVAZPD7I5FwcBlPH98TJ0hNUtnDVxkJ0pde8ZcQdYFkfYFNnX+7f06ps/TY
CtchEAlx9cXBfBnImO4mB2Y89uRh7HRA2BiUmme4Xjy5P3qyvOnx2lIiH2hFyXJ0
6N8UcBEviZTZd+D6FR5TJ8aNOhCwktutsrwKeSj4jrIWSD0vPlkQTbxUrm6x+7/i
JBwOsMNA5UB+SZxAn8BtcvzpxHaj1l3WRddZcykTfz6k8fuQfJCdp1aN47guLXWt
HTDvXeOlXpDStOlIwwMvh2i42ZaLas2C2B8rrX6pMmzazJLZcth8ZIyhfuB1WcMv
AQ==
-----END CERTIFICATE-----"#;

fn signer_cert_id() -> Result<String, Box<dyn Error>> {
    let cert = X509::from_pem(BAMBUCONNECT_CERT_PEM.as_bytes())?;
    let serial = cert
        .serial_number()
        .to_bn()?
        .to_hex_str()?
        .to_string()
        .to_ascii_lowercase();
    let issuer_cn = cert
        .issuer_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .ok_or("missing issuer CN in signing certificate")?
        .data()
        .as_utf8()?
        .to_string();

    Ok(format!("{serial}CN={issuer_cn}"))
}

fn build_header(payload_str: &str, signature_b64: &str) -> Result<Value, Box<dyn Error>> {
    Ok(json!({
        "sign_ver": SIGN_VER,
        "sign_alg": SIGN_ALG,
        "sign_string": signature_b64,
        "cert_id": signer_cert_id()?,
        "payload_len": payload_str.len(),
    }))
}

/// Signs the provided top-level JSON object and appends a `header` field.
///
/// The signature is computed over the JSON payload bytes without the `header` key.
pub fn sign_payload_value(payload: &Value) -> Result<String, Box<dyn Error>> {
    let mut object = match payload {
        Value::Object(obj) => obj.clone(),
        _ => return Err("payload must be a JSON object".into()),
    };

    object.remove("header");

    let payload_no_header = Value::Object(object.clone());
    let payload_str = serde_json::to_string(&payload_no_header)?;

    let key = PKey::private_key_from_pem(BAMBUCONNECT_PRIVATE_KEY_PEM.as_bytes())?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(payload_str.as_bytes())?;
    let signature = signer.sign_to_vec()?;
    let signature_b64 = BASE64.encode(signature);

    object.insert(
        "header".to_string(),
        build_header(&payload_str, &signature_b64)?,
    );

    Ok(serde_json::to_string(&Value::Object(object))?)
}

/// Signs a JSON payload string and appends a `header` field.
pub fn sign_payload_str(payload: &str) -> Result<String, Box<dyn Error>> {
    let value: Value = serde_json::from_str(payload)?;
    sign_payload_value(&value)
}

/// Returns the signer certificate id in the format expected by printer firmware.
pub fn signer_certificate_id() -> Result<String, Box<dyn Error>> {
    signer_cert_id()
}

/// Returns MQTT signing material for advanced integrations.
pub fn bootstrap_signing_material() -> (&'static str, &'static str) {
    (BAMBUCONNECT_PRIVATE_KEY_PEM, BAMBUCONNECT_CERT_PEM)
}

#[cfg(test)]
mod tests {
    use super::{sign_payload_str, signer_certificate_id};
    use serde_json::Value;

    #[test]
    fn certificate_id_matches_expected_format() {
        let cert_id = signer_certificate_id().expect("cert id should parse");
        assert!(cert_id.starts_with("ee3cac0712ceeacda8b7fbc42e74ba2c"));
        assert!(cert_id.contains("CN=GLOF3813734089.bambulab.com"));
    }

    #[test]
    fn signed_payload_has_expected_header_fields() {
        let payload = r#"{"print":{"sequence_id":"0","command":"pause"}}"#;
        let signed = sign_payload_str(payload).expect("payload should sign");
        let value: Value = serde_json::from_str(&signed).expect("signed payload should be json");

        let header = value
            .get("header")
            .and_then(Value::as_object)
            .expect("header object should be present");

        assert_eq!(header.get("sign_ver").and_then(Value::as_str), Some("v1.0"));
        assert_eq!(
            header.get("sign_alg").and_then(Value::as_str),
            Some("RSA_SHA256")
        );
        assert!(
            header
                .get("sign_string")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
        );
        assert!(
            header
                .get("cert_id")
                .and_then(Value::as_str)
                .is_some_and(|s| s.contains("CN="))
        );
        assert!(header.get("payload_len").and_then(Value::as_u64).is_some());
    }

    #[test]
    fn payload_len_uses_utf8_bytes() {
        let payload = r#"{"print":{"command":"gcode_line","param":"M117 hello"}}"#;
        let signed = sign_payload_str(payload).expect("payload should sign");
        let value: Value = serde_json::from_str(&signed).expect("signed payload should be json");

        let mut without_header: serde_json::Map<String, Value> = value
            .as_object()
            .expect("signed payload should be object")
            .clone();
        without_header.remove("header");
        let unsigned_str = serde_json::to_string(&Value::Object(without_header))
            .expect("unsigned payload should serialize");

        let payload_len = value
            .get("header")
            .and_then(Value::as_object)
            .and_then(|h| h.get("payload_len"))
            .and_then(Value::as_u64)
            .expect("payload_len should be present");

        assert_eq!(payload_len as usize, unsigned_str.len());
    }
}