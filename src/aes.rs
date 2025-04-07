use crate::utils;
use anyhow::anyhow;

/// Remove padding from a slice of bytes
/// Due to padding being added to the end of the data, we have to remove it
/// after decryption. A priori, we don't know how much padding was added, so
/// we have to guess. We do this by looking for repeating bytes at the end
/// of the data.
/// NOTE: Only to be used in this context
fn remove_padding(mut v: Vec<u8>) -> Vec<u8> {
    // Count the number of repeating bytes at the end of the slice
    let n_repeating_end = v.iter().rev().take_while(|&n| *n == v[v.len() - 1]).count();
    // Return the slice without the repeating bytes
    v.truncate(v.len() - n_repeating_end);
    v
}

/// Encrypt data using AES-128 in ECB mode
///
/// ECB mode works by splitting each block of data into equal-sized blocks and
/// encrypting them individually with the same key. This means that identical
/// blocks of data will be encrypted to the same output, which can leak
/// information about the data.
/// WARN: ECB mode is insecure and should not be used in practice
pub fn encrypt_ecb<const BYTES: usize>(data: &[u8], key: &[u8; BYTES]) -> Vec<u8> {
    data.chunks(BYTES)
        // Ensure blocks are padded to the key length
        .map(|block| utils::add_padding(block, key.len()))
        // Encrypt each block and flatten the result
        .flat_map(|block| utils::bytes_xor(&block, key))
        .collect()
}

/// Decrypt data using AES-128 in ECB mode
///
/// ECB mode works by splitting each block of data into equal-sized blocks and
/// encrypting them individually with the same key. This means that identical
/// blocks of data will be encrypted to the same output, which can leak
/// information about the data.
/// WARN: ECB mode is insecure and should not be used in practice
pub fn decrypt_ecb<const BYTES: usize>(
    data: &[u8],
    key: &[u8; BYTES],
) -> Result<Vec<u8>, anyhow::Error> {
    // Ensure data length is a multiple of key length
    if data.len() % BYTES != 0 {
        return Err(anyhow!("data length is not a multiple of key length"));
    }
    // Decrypt each block and flatten the result
    // The last block may have padding, so we remove it before XOR
    Ok(remove_padding(
        data.chunks(BYTES)
            .flat_map(|block| utils::bytes_xor(block, key))
            .collect(),
    ))
}

/// Encrypt data using AES-128 in CBC mode
/// CBC encryption uses the previously encrypted block to encrypt the next block. Since the first
/// block will not have a predecessor, an initialization vector is needed to make this encryption
/// method work.
pub fn encrypt_cbc<const BYTES: usize>(
    data: &[u8],
    key: &[u8; BYTES],
    iv: &mut [u8; BYTES],
) -> Vec<u8> {
    data.chunks(BYTES)
        // Add padding to each block to ensure they're the same length.
        .map(|plaintext_block| utils::add_padding(plaintext_block, BYTES))
        .flat_map(|plaintext_block| {
            // P_i XOR IV
            utils::bytes_xor_in_place(iv, &plaintext_block);
            // P_i XOR IV XOR K = C_i
            utils::bytes_xor_in_place(iv, key);
            // Copy C_i so we can use IV next round
            iv.to_vec()
        })
        .collect()
}

/// Decrypt data using AES-128 in CBC mode
/// CBC decryption uses the previously encrypted block to decrypt the next block. Since the
/// last block will not have a successor, an initialization vector is needed to make this decryption
/// method work.
pub fn decrypt_cbc<const BYTES: usize>(
    data: &[u8],
    key: &[u8; BYTES],
    iv: &mut [u8; BYTES],
) -> Result<Vec<u8>, anyhow::Error> {
    // Encrypted data must be a multiple of key length
    if data.len() % key.len() != 0 {
        return Err(anyhow!("data length not multiple of key length"));
    }

    Ok(remove_padding(
        data.chunks(BYTES)
            .flat_map(|ciphertext_block| {
                let almost_plaintext_block = utils::bytes_xor(ciphertext_block, key);
                let plaintext_block = utils::bytes_xor(&almost_plaintext_block, iv);
                iv.copy_from_slice(ciphertext_block);
                plaintext_block
            })
            .collect(),
    ))
}

#[test]
fn test_cbc_mode() -> Result<(), anyhow::Error> {
    const LOREM: &str = include_str!("../data/lorem_ipsum.txt");
    const KEY: &[u8; 16] = b"YELLOW SUBMARINE";

    let mut iv = [0u8; 16];
    let encrypted = encrypt_cbc(LOREM.as_bytes(), &KEY, &mut iv);
    // Reset IV to the original value
    // This is important because the IV is modified during encryption
    iv = [0u8; 16];
    let result = decrypt_cbc(&encrypted, &KEY, &mut iv)?;
    utils::require_eq(&result, &LOREM.as_bytes().to_vec())?;
    Ok(())
}

#[test]
fn test_ecb_mode() -> Result<(), anyhow::Error> {
    const LOREM: &str = include_str!("../data/lorem_ipsum.txt");
    const KEY: &[u8; 16] = b"YELLOW SUBMARINE";
    let encrypted = encrypt_ecb(LOREM.as_bytes(), &KEY);
    let result = decrypt_ecb(&encrypted, &KEY)?;
    utils::require_eq(&result, &LOREM.as_bytes().to_vec())?;
    Ok(())
}
