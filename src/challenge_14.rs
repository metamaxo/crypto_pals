use crate::aes_128;
use crate::anyhow;
use crate::utils;
use base64::{Engine, engine as _, engine::general_purpose::STANDARD};
use std::collections::HashMap;

// for challenge 14 we'll use the same input as challenge 12.
fn challenge_14() -> Result<(), anyhow::Error> {
    const HEXSTRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    const TEST_STRING: &[u8] = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let key: Vec<u8> = vec![
        119, 120, 57, 66, 93, 72, 89, 114, 103, 91, 105, 56, 79, 51, 84, 80,
    ];
    const EXPECTED: &str = "Rollin' in my 5.0. With my rag-top down so my hair can blow. The girlies on standby waving just to say hi. Did you stop? No, I just drove by";

    // Oracle function that enctypts buffers under ECB mode using a consistent but unknown key. Before
    // decrypting the base64 decoded unknown string gets appended to the plaintext.
    // Function should produce: AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
    fn challenge_14_oracle(
        prefix: &[u8],
        unknown_string: &[u8],
        attack_string: &[u8],
        key: &[u8],
    ) -> Vec<u8> {
        //Append unknown string to plaintext
        let mut plaintext = prefix.to_vec();
        plaintext.extend_from_slice(attack_string);
        plaintext.extend_from_slice(unknown_string);
        //encrypt using ecb mode
        aes_128::encrypt_aes128_ecb(&plaintext, key).unwrap()
    }

    //This detection mode only works when the encrypted plaintext is a string of identical bytes.
    //Because ebc uses a the same key to encrypt each block, the amound of identical bytes in the
    //ciphertext will be significantly higher. This means when we add every byte to a hashmap, the
    //length of the hashmap will be shorter for ebc mode.
    fn detect_encryption_mode(cipher: Vec<u8>) -> String {
        let uniqueness = (cipher
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len() as f64)
            / (cipher.len() as f64);
        if uniqueness < 0.8 {
            "ebc".to_owned()
        } else {
            "cbc".to_owned()
        }
    }

    //Feed identical bytes of string to the function 1 at a time. Start with 1 byte, then increase
    //byte size to discover the block size of the cypher. If the cipher length jumps with more than
    //1 byte, this means the block is getting padded and we have found the blocksize.
    fn determine_block_size(key: &[u8]) -> usize {
        let initial_len = challenge_14_oracle(&[b'A'; 2], &[b'A'; 2], &[b'A'; 16], key).len();
        (2..64)
            .find_map(|x| {
                let input_bytes = vec![b'A'; x];
                let current_len =
                    challenge_14_oracle(&[b'A'; 2], &[b'A'; 16], &input_bytes, key).len();
                let diff = current_len - initial_len;
                if diff > 1 { Some(x + 2) } else { None }
            })
            .unwrap_or(0) // Or handle the case where no block size change is detected differently
    }

    fn determine_prefix_size(prefix: &[u8], key: &[u8]) -> usize {
        // Encrypt with the prefix + our starting point + our blocksize for the initial length.
        let initial_len = challenge_14_oracle(prefix, &[b'A'; 2], &[b'A'; 16], key).len();
        (2..64)
            .find_map(|x| {
                let input_bytes = vec![b'A'; x];
                let current_len = challenge_14_oracle(prefix, &[b'A'; 16], &input_bytes, key).len();
                let diff = current_len - initial_len;
                if diff > 1 { Some(x) } else { None }
            })
            .unwrap_or(0) // Or handle the case where no block size change is detected differently
    }

    // Create a byte dictionary for every possible byte making sure its encrypted so we can compare
    // it later.
    fn generate_byte_dictionary(key: &[u8]) -> HashMap<Vec<u8>, String> {
        (0..=255)
            .map(|i| {
                let mut k = vec![b'A'; 15];
                let byte = i as u8;
                k.push(byte);
                let encrypted_k = challenge_14_oracle(&k, &k, &k, key);
                (
                    encrypted_k[0..16].to_vec(),
                    String::from_utf8_lossy(&[byte]).to_string(),
                )
            })
            .collect()
    }

    // Base64 decode the string.
    let unknown_string = STANDARD
        .decode(HEXSTRING)
        .map_err(|_| anyhow!("unable to decode base64"))?;

    // We generate our random prefix.
    let prefix = utils::random_byte_vec();

    // Detecting block size, then checking if the detection works.
    let blocksize = determine_block_size(&key);
    assert_eq!(blocksize, 16);

    // We know the format we're enctypting in:
    // AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
    // Since we can only control the 'attacker-controlled' part, we can increade the length until
    // the first jump, indicating there is padding being added.
    let test_prefix = [b'A'; 8];
    let prefix_size_test = blocksize - determine_prefix_size(&test_prefix, &key);
    assert_eq!(test_prefix.len(), prefix_size_test);
    let prefix_size = blocksize - determine_prefix_size(&prefix, &key);

    // Detecting enctyption mode, then checking if detection works.
    let detection_cipher = challenge_14_oracle(&unknown_string, TEST_STRING, TEST_STRING, &key);
    let detected_mode = detect_encryption_mode(detection_cipher);
    assert_eq!("ebc", detected_mode);

    // Generate byte dictionary and short string. We will use this to try break the encryption.
    let byte_dictionary = generate_byte_dictionary(&key);

    // Now we can take the blocksize, subtract the prefix length and adjust our attack string.
    let padding_size = blocksize - prefix_size;
    let attack_string_length = padding_size + 15;
    let attack_string = (0..attack_string_length).map(|_| b'A').collect::<Vec<u8>>();
    let total_length = prefix_size + attack_string.len();
    let start = total_length - 15;
    let finish = total_length + 1;

    // We will append the unknown string to the short string, resulting in a block with 15 known bytes,
    // and the first byte of the unknown string.
    let result: Vec<String> = (0..unknown_string.len())
        .filter_map(|x| {
            let first_block =
                challenge_14_oracle(&prefix, &unknown_string[x..], &attack_string, &key)
                    [start..finish]
                    .to_vec();
            byte_dictionary // Compare with our dict to find corresponding byte.
                .iter()
                .find(|(k, _)| **k == first_block)
                .map(|(_, v)| v.to_string())
        })
        .collect();

    // Remove new-line symbols and trim whitespace, then compare result with expected result.
    let string_result = result.join("").trim().replace("\n", ". ");
    assert_eq!(string_result, EXPECTED);

    Ok(())
}

#[test]
fn challenge_14_test() -> Result<(), anyhow::Error> {
    challenge_14()
}
