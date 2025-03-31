use crate::utils;
use anyhow::anyhow;

/// Encrypt data using AES-128 in ECB mode
///
/// ECB mode works by splitting each block of data into equal-sized blocks and
/// encrypting them individually with the same key. This means that identical
/// blocks of data will be encrypted to the same output, which can leak
/// information about the data.
/// WARN: ECB mode is insecure and should not be used in practice
pub fn encrypt_aes128_ecb_mode(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.chunks(key.len())
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
pub fn decrypt_aes128_ecb_mode(data: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    /// Remove padding from a slice of bytes
    /// Due to padding being added to the end of the data, we have to remove it
    /// after decryption. A priori, we don't know how much padding was added, so
    /// we have to guess. We do this by looking for repeating bytes at the end
    /// of the data.
    /// NOTE: Only to be used in this context
    fn remove_padding(slice: &[u8]) -> &[u8] {
        // Count the number of repeating bytes at the end of the slice
        let n_repeating_end = slice
            .iter()
            .rev()
            .take_while(|&n| *n == slice[slice.len() - 1])
            .count();
        // Return the slice without the repeating bytes *as a reference*
        &slice[0..slice.len() - n_repeating_end]
    }
    // Ensure data length is a multiple of key length
    if data.len() % key.len() != 0 {
        return Err(anyhow!("data length is not a multiple of key length"));
    }
    // Decrypt each block and flatten the result
    // The last block may have padding, so we remove it before XOR
    Ok(data
        .chunks(key.len())
        .enumerate()
        .flat_map(|(i, block)| {
            // If this is the last chunk, remove padding before XOR
            if i == data.len() / key.len() - 1 {
                utils::bytes_xor(remove_padding(block), key)
            } else {
                utils::bytes_xor(block, key)
            }
        })
        .collect())
}

#[test]
fn test_aes128_2() -> Result<(), anyhow::Error> {
    const LOREM: &str = include_str!("../data/lorem_ipsum.txt");
    const KEY: &str = "YELLOW SUBMARINE";
    let encrypted = encrypt_aes128_ecb_mode(LOREM.as_bytes(), KEY.as_bytes());
    let result = decrypt_aes128_ecb_mode(&encrypted, KEY.as_bytes())?;
    let result = String::from_utf8_lossy(&result);
    if result != LOREM {
        return Err(anyhow!("unexpected result"));
    }
    Ok(())
}
