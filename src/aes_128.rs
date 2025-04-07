use crate::utils;

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use anyhow::{Result, anyhow};

/// Pad using PKCS#7
fn pad_pkcs7(data: &[u8]) -> Vec<u8> {
    let pad_len = 16 - (data.len() % 16);
    data.iter()
        .cloned()
        .chain(std::iter::repeat(pad_len as u8).take(pad_len))
        .collect()
}

/// Remove PKCS#7 padding
fn unpad_pkcs7(mut data: Vec<u8>) -> Vec<u8> {
    if let Some(&pad) = data.last() {
        let len = data.len();
        if (pad as usize) <= len && data[len - pad as usize..].iter().all(|&b| b == pad) {
            data.truncate(len - pad as usize);
        }
    }
    data
}

/// Encrypt with AES-128 in CBC mode
pub fn encrypt_aes128_cbc(data: &[u8], key: &[u8; 16], iv: &mut [u8; 16]) -> Result<Vec<u8>> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let padded = pad_pkcs7(data);
    let mut result = Vec::with_capacity(padded.len());

    padded.chunks(16).for_each(|block| {
        let xored: Vec<u8> = block.iter().zip(iv.iter()).map(|(a, b)| a ^ b).collect();
        let mut buf = GenericArray::clone_from_slice(&xored);
        cipher.encrypt_block(&mut buf);
        iv.copy_from_slice(&buf);
        result.extend(buf);
    });

    Ok(result)
}

/// Decrypt with AES-128 in CBC mode
pub fn decrypt_aes128_cbc(data: &[u8], key: &[u8; 16], iv: &mut [u8; 16]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(anyhow!("ciphertext length must be a multiple of 16"));
    }

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut result = Vec::with_capacity(data.len());

    data.chunks(16).for_each(|block| {
        let mut buf = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut buf);
        let plain: Vec<u8> = buf.iter().zip(iv.iter()).map(|(a, b)| a ^ b).collect();
        iv.copy_from_slice(block);
        result.extend(plain);
    });

    Ok(unpad_pkcs7(result))
}

/// Encrypt with AES-128 in ECB mode
pub fn encrypt_aes128_ecb(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let padded = pad_pkcs7(data);
    let mut result = Vec::with_capacity(padded.len());

    padded.chunks(16).for_each(|block| {
        let mut buf = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut buf);
        result.extend(buf);
    });

    Ok(result)
}

/// Decrypt with AES-128 in ECB mode
pub fn decrypt_aes128_ecb(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(anyhow!("ciphertext length must be a multiple of 16"));
    }

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut result = Vec::with_capacity(data.len());

    data.chunks(16).for_each(|block| {
        let mut buf = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut buf);
        result.extend(buf);
    });

    Ok(unpad_pkcs7(result))
}

#[test]
fn test_aes128_cbc_mode() -> Result<(), anyhow::Error> {
    const LOREM: &str = include_str!("../data/lorem_ipsum.txt");
    const KEY: &[u8; 16] = b"YELLOW SUBMARINE";
    const IV: &[u8; 16] = b"0000000000000000";

    let encrypted = encrypt_aes128_cbc(LOREM.as_bytes(), KEY, &mut IV.clone())?;
    let result = decrypt_aes128_cbc(&encrypted, KEY, &mut IV.clone())?;
    utils::require_eq(result.as_slice(), LOREM.as_bytes())?;
    Ok(())
}

#[test]
fn test_aes128_ecb_mode() -> Result<(), anyhow::Error> {
    const LOREM: &str = include_str!("../data/lorem_ipsum.txt");
    const KEY: &[u8; 16] = b"YELLOW SUBMARINE";
    let encrypted = encrypt_aes128_ecb(LOREM.as_bytes(), KEY)?;
    let result = decrypt_aes128_ecb(&encrypted, KEY)?;
    utils::require_eq(result.as_slice(), LOREM.as_bytes())?;
    Ok(())
}
