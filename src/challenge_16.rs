use crate::{
    aes_128::{self, pad_pkcs7},
    utils,
};
use anyhow::anyhow;

// Formats the data following challenge instructions, then returns the encrypted data.
fn challenge_16_oracle(data: &str, key: &[u8], iv: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
    const PREPEND: &str = "comment1=cooking%20MCs;userdata=";
    const APPEND: &str = ";comment2=%20like%20a%20pound%20of%20bacon";
    // Quote out ";" and "=" from data.
    let clean_data = data.replace("=", "\"=\"").replace(";", "\";\"");
    // format the data and convert to bytes.
    let full_data = format!("{}{}{}", PREPEND, clean_data, APPEND);
    let padded_data = aes_128::pad_pkcs7(full_data.as_bytes());
    // Pad out the input to the 16-byte AES block length and encrypt it under the random AES key.
    aes_128::encrypt_aes128_cbc(&padded_data, key, &mut iv.clone())
}

fn challenge_16_decryptor(data: &[u8], key: &[u8], iv: Vec<u8>) -> Result<bool, anyhow::Error> {
    // Decrypt string
    let decrypted_data = aes_128::decrypt_aes128_cbc(data, key, &mut iv.clone())?;
    let decrypted_data_string = String::from_utf8_lossy(&decrypted_data);
    println!("{}", decrypted_data_string);
    // Look for characters ";admin=true;"
    for string in decrypted_data_string.split(";") {
        // If characters exist, return true.
        if string.contains("admin=true") {
            return Ok(true);
        } else {
            continue;
        }
    }
    Ok(false)
}

// For this challenge we alter the encrypted data to make ourselves admin.
fn challenge_16() -> Result<(), anyhow::Error> {
    // Input string, we will change the second block to our target.
    const INPUT: &str = "AAAAAAAAAAAAAAAAAadminAtrueAAAAA";
    // generate a random AES key
    let key = utils::generate_16_byte_key();
    // iv shouldn't really matter, so we generate a random one using the random key generator.
    let iv = utils::generate_16_byte_key();
    // Let oracle encrypt the data after formatting it according to challenge instructions.
    let mut encrypted = challenge_16_oracle(INPUT, &key, iv.clone().to_vec())?;
    // First we xor the encrypted bytes with 'A' to get the corresponding byte used to xor our
    // target bytes. then we xor these with the characters we need before replacing them in our
    // cipher. We know the prepend is 2 blocks long, so we adjust our index accordingly.
    for (i, c) in [(32, b';'), (38, b'='), (43, b'=')].iter() {
        encrypted[*i] ^= b'A' ^ c;
    }
    // We decrypt our cipher to check if we're now admin.
    if challenge_16_decryptor(&encrypted, &key, iv.clone().to_vec())? {
        Ok(())
    } else {
        Err(anyhow!("admin=true not found"))
    }
}

#[test]
fn challenge_16_test() -> Result<(), anyhow::Error> {
    challenge_16()
}
