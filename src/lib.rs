#![forbid(unsafe_code)]
#![deny(clippy::implicit_return)]
#![allow(clippy::needless_return)]

use wasm_bindgen::prelude::*;

use digest::Digest;
use libaes::Cipher;

fn check_master_key(key: &str) -> Result<&[u8; 16], &'static str> {
    return match key.len() {
        0 => return Ok(b"p1a2l3o4a5l6t7o8"),
        16 => return Ok(<&[u8; 16]>::try_from(key.as_bytes()).unwrap()),
        _ => Err("Master key must be exactly 16 characters"),
    };
}

// md5("pannetwork")
const KDF_SALT: &[u8; 16] = b"\x75\xb8\x49\x83\x90\xbc\x2a\x65\x9c\x56\x93\xe7\xe5\xc5\xf0\x24";
fn panos_derive_key(key: &[u8; 16]) -> [u8; 32] {
    let digest = md5_digest(<&[u8; 32]>::try_from([*key, *KDF_SALT].concat().as_slice()).unwrap());
    return <[u8; 32]>::try_from([digest, digest].concat().as_slice()).unwrap();
}

#[wasm_bindgen]
pub fn panos_decrypt(key: &str, input: &str) -> String {
    let master_key = check_master_key(key);

    if let Err(e) = master_key {
        return format!("Invalid master key: {}", e);
    }

    let mut input_iter = input.chars();

    let prefix = input_iter.by_ref().take(1).collect::<String>();
    match prefix.as_str() {
        "-" => {}
        s => return format!("Input starts with '{}', expected '-'", s),
    }
    drop(prefix);

    let version = base64::decode(input_iter.by_ref().take(4).collect::<String>());
    match version {
        Err(e) => return format!("Failed to base64-decode version: {}", e),
        Ok(version_vec) => match version_vec.as_slice() {
            [1u8] => {}
            _ => return "Incompatible version detected".to_string(),
        },
    }

    // base64(sha1) is 28 bytes
    let hash_vec = base64::decode(input_iter.by_ref().take(28).collect::<String>());
    if let Err(e) = hash_vec {
        return format!("Failed to base64-decode hash: {}", e);
    }
    let hash = hash_vec.as_ref().unwrap().as_slice();

    let ct = base64::decode(input_iter.by_ref().collect::<String>());
    if let Err(e) = ct {
        return format!("Failed to base64-decode value: {}", e);
    }
    let ct = ct.unwrap();

    let cleartext = match ct.len() {
        0 => Vec::new(),
        _ => {
            if ct.len() % 16 != 0 {
                return "Invalid ciphertext length".to_string();
            }

            let iv = [0u8; 16];
            let derived_key = panos_derive_key(master_key.unwrap());
            let cipher = Cipher::new_256(&derived_key);
            cipher.cbc_decrypt(&iv, ct.as_slice())
        }
    };

    let cleartext_hash = sha1_digest(&cleartext);

    return match hash == cleartext_hash {
        true => String::from_utf8(cleartext)
            .unwrap_or_else(|_| return "Value cannot be decoded as UTF-8".to_string()),
        false => "Integrity check failed".to_string(),
    };
}

#[wasm_bindgen]
pub fn panos_encrypt(key: &str, input: &str) -> String {
    let master_key = check_master_key(key);

    if let Err(e) = master_key {
        return format!("Invalid master key: {}", e);
    }

    if input.chars().count() == 0 {
        return "No input".to_string();
    }

    // version 1
    let version = base64::encode(&[1u8]);

    // integrity hash to verify decryption result
    let hash = base64::encode(sha1_digest(&input));

    let iv = [0u8; 16];
    let derived_key = panos_derive_key(master_key.unwrap());
    let cipher = Cipher::new_256(&derived_key);
    let ct = base64::encode(cipher.cbc_encrypt(&iv, input.as_bytes()));

    let mut out = "-".to_owned();
    out.push_str(&version);
    out.push_str(&hash);
    out.push_str(&ct);

    return out;
}

fn md5_digest(input: &impl AsRef<[u8]>) -> [u8; 16] {
    let digest = md5::Md5::digest(input);
    return <[u8; 16]>::try_from(digest.as_slice()).unwrap();
}

fn sha1_digest(input: &impl AsRef<[u8]>) -> [u8; 20] {
    let digest = sha1::Sha1::digest(input);
    return <[u8; 20]>::try_from(digest.as_slice()).unwrap();
}
