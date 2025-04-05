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
                remove_padding(&utils::bytes_xor(block, key)).to_owned()
            } else {
                utils::bytes_xor(block, key)
            }
        })
        .collect())
}

/// CBC encryption uses the previously encrypted block to encrypt the next block. Since the first
/// block will not have a predecessor, an initialization vector is needed to make this encryption
/// method work.
/// WARN: The IV and padding scheme used in this function are not secure, this function should not
/// be used in practice.
pub fn encrypt_aes128_cbc_mode(data: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    // Create the IV
    let mut previous_encrypted_block = vec![0u8; key.len()];

    // For every block, xor with previous block, then xor it with the key to encrypt,
    // If the last block is shorter than the block size, padding will be added.
    Ok(data
        .chunks(key.len())
        // Add padding to each block to ensure they're the same length.
        .map(|block| utils::add_padding(block, key.len()))
        // First xor the block with previously encrypted ciphertext block. next xor the block with the key
        .flat_map(|block| {
            let block_to_encrypt = utils::bytes_xor(&block, &previous_encrypted_block);
            let ciphertext_block = utils::bytes_xor(&block_to_encrypt, key);
            // The current ciphertext block becomes the previous for the next iteration.
            previous_encrypted_block = ciphertext_block.to_vec();
            ciphertext_block
        })
        .collect())
}

/// For decrypting, we use te same steps as the encryption function, only reversed.
/// WARN: The IV and padding scheme used in this function are not secure, this function should not
/// be used in practice.
pub fn decrypt_aes128_cbc_mode(data: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    // Function to remove padding if needed.
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
    // Encrypted data must be a multiple of key length
    if data.len() % key.len() != 0 {
        return Err(anyhow!("data length not multiple of key length"));
    }
    // Create the IV
    let mut previous_ciphertext_block = vec![0u8; key.len()];
    // For every block, xor with key to decrypt, then xor it with the previous block to get the
    // plaintext block.
    let result: Vec<u8> = data
        .chunks(key.len())
        .flat_map(|block| {
            // Decrypt the current block
            let decrypted_block = utils::bytes_xor(block, key);
            // XOR the decrypted block with the previous ciphertext block
            let plaintext_block = utils::bytes_xor(&decrypted_block, &previous_ciphertext_block);
            // The current ciphertext block becomes the previous for the next iteration
            previous_ciphertext_block = block.to_vec();
            plaintext_block
        })
        .collect();

    // Remove padding from the last block
    Ok(remove_padding(&result).to_vec())
}

#[test]
fn test_aes128_cbc_mode() -> Result<(), anyhow::Error> {
    const LOREM: &str = include_str!("../data/lorem_ipsum.txt");
    const KEY: &str = "YELLOW SUBMARINE";

    let encrypted = encrypt_aes128_cbc_mode(LOREM.as_bytes(), KEY.as_bytes()).unwrap();
    let result = decrypt_aes128_cbc_mode(&encrypted, KEY.as_bytes()).unwrap();
    if result != LOREM.as_bytes() {
        return Err(anyhow!("unexpected result"));
    }
    Ok(())
}

#[test]
fn test_aes128_ecb_mode() -> Result<(), anyhow::Error> {
    const LOREM: &str = include_str!("../data/lorem_ipsum.txt");
    const KEY: &str = "YELLOW SUBMARINE";
    let encrypted = encrypt_aes128_ecb_mode(LOREM.as_bytes(), KEY.as_bytes());
    let result = decrypt_aes128_ecb_mode(&encrypted, KEY.as_bytes())?;
    if result != LOREM.as_bytes() {
        return Err(anyhow!("unexpected result"));
    }
    Ok(())
}
