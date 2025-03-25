use anyhow::anyhow;

use openssl::symm::{Cipher, decrypt, encrypt};

pub fn decrypt_aes128(data: &[u8], key: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    decrypt(Cipher::aes_128_ecb(), key, Some(&data[..key.len()]), data)
}

pub fn encrypt_aes128(data: &[u8], key: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    encrypt(Cipher::aes_128_ecb(), key, Some(&data[..key.len()]), data)
}

#[test]
fn test_aes128() -> Result<(), anyhow::Error> {
    const LOREM: &str = include_str!("../data/lorem_ipsum.txt");
    const KEY: &str = "YELLOW SUBMARINE";
    let encrypted = encrypt_aes128(LOREM.as_bytes(), KEY.as_bytes())?;
    let result = decrypt_aes128(&encrypted, KEY.as_bytes())?;
    let result = String::from_utf8_lossy(&result);
    if result != LOREM {
        return Err(anyhow!("unexpected result"));
    }
    Ok(())
}
