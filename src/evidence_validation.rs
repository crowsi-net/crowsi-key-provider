use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

pub(crate) fn evidence_digest_matches(encoded: &str, expected: &str) -> bool {
    if !is_digest(expected) {
        return false;
    }
    let Some(decoded) = decoded_canonical(encoded, 16, 16_384) else {
        return false;
    };
    format!("{:x}", Sha256::digest(decoded)) == expected
}

pub(crate) fn canonical_base64(value: &str, minimum: usize, maximum: usize) -> bool {
    decoded_canonical(value, minimum, maximum).is_some()
}

fn decoded_canonical(value: &str, minimum: usize, maximum: usize) -> Option<Vec<u8>> {
    if !(minimum..=maximum).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return None;
    }
    let decoded = STANDARD.decode(value).ok()?;
    (STANDARD.encode(&decoded) == value).then_some(decoded)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
