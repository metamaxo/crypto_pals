use crate::utils;
use anyhow::anyhow;

pub fn encrypt_aes128(data: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let blocks = data.chunks(key.len());
    let mut results: Vec<u8> = Vec::new();
    for block in blocks {
        if block.len() == key.len() {
            results.extend_from_slice(utils::bytes_xor(block, key).as_ref());
        } else {
            results.extend_from_slice(
                utils::bytes_xor(utils::add_padding(block, key.len()).as_ref(), key).as_ref(),
            )
        }
    }
    Ok(results)
}
pub fn remove_padding(slice: &[u8]) -> Vec<u8> {
    let mut result: &[u8] = Vec::new().as_ref();
    let mut v = Vec::new();
    for (index, byte) in slice.iter().enumerate() {
        if slice.iter().filter(|&n| n == byte).count() > 2 {
            v.push(index)
        }
    }
    if v.len() > 1 {
        result = &slice[0..v[0]];
    } else {
        result = slice;
    }
    result.to_owned()
}

pub fn decrypt_aes128(data: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let blocks = data
        .chunks_exact(key.len())
        .take(data.len() / key.len() - 1);
    let mut results: Vec<u8> = Vec::new();
    for block in blocks {
        results.extend_from_slice(utils::bytes_xor(block, key).as_ref());
    }
    let last_chunk = data.chunks(key.len()).last().unwrap();
    let last_chunk_decrypted = utils::bytes_xor(last_chunk, key);
    let last = remove_padding(&last_chunk_decrypted);
    results.extend_from_slice(&last);

    Ok(results)
}

#[test]
fn test_aes128_2() -> Result<(), anyhow::Error> {
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
