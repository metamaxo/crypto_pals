#![allow(dead_code, unused_imports)]
use base64::{Engine, engine as _, engine::general_purpose::STANDARD};
use rand::Rng;
use std::collections::HashMap;
mod aes_128;
mod repeated_xor;
mod single_byte_xor;
mod traits;
mod types;
mod utils;

use traits::{
    BytesBase64Ext, BytesExt, BytesHexExt, BytesHexLinesExt as _, BytesStrExt,
    BytesStrLinesExt as _,
};

use ::anyhow::anyhow;

fn challenge_1() -> Result<(), anyhow::Error> {
    const INPUT: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const EXPECTED: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    utils::require_eq(
        <Vec<u8>>::try_from_hex(INPUT)?.to_base64().as_str(),
        EXPECTED,
    )
}

fn challenge_2() -> Result<(), anyhow::Error> {
    const INPUT: &str = "1c0111001f010100061a024b53535009181c";
    const BUFFER: &str = "686974207468652062756c6c277320657965";
    const EXPECTED: &str = "746865206b696420646f6e277420706c6179";

    let result = utils::bytes_xor(
        &<Vec<u8>>::try_from_hex(INPUT)?,
        &<Vec<u8>>::try_from_hex(BUFFER)?,
    )
    .to_hex();
    utils::require_eq(result.as_str(), EXPECTED)
}

fn challenge_3() -> Result<(), anyhow::Error> {
    const INPUT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const EXPECTED: u8 = 88;
    let result =
        single_byte_xor::try_break(&<Vec<u8>>::try_from_hex(INPUT)?).ok_or(anyhow!("no result"))?;
    utils::require_eq(result.byte, EXPECTED)
}

fn challenge_4() -> Result<(), anyhow::Error> {
    const FILE: &str = include_str!("../data/file_1.txt");
    const EXPECTED: &str = "Now that the party is jumping\n";
    let lines = <Vec<Vec<u8>>>::try_from_hex(FILE)?;

    let Some((line, result)) = lines
        .iter()
        .zip(lines.iter().map(|line| single_byte_xor::try_break(line)))
        .flat_map(|(line, result)| result.map(|result| (line, result)))
        .min_by(|(_, left_result), (_, right_result)| left_result.cmp(right_result))
    else {
        return Err(anyhow!("no result"));
    };

    let s = String::from_utf8_lossy(&utils::bytes_xor(line, &[result.byte])).to_string();
    utils::require_eq(s.as_str(), EXPECTED)
}

fn challenge_5() -> Result<(), anyhow::Error> {
    const FILE: &str =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const EXPECTED: &str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    const KEY: &str = "ICE";

    let file = <Vec<u8>>::from_str(FILE);
    let expected_lines = <Vec<u8>>::try_from_hex(EXPECTED)?;

    let key = KEY.as_bytes();
    let decrypted = utils::bytes_xor(&file, key);
    utils::require_eq(decrypted, expected_lines)
}

fn challenge_6() -> Result<(), anyhow::Error> {
    const EXPECTED: u32 = 18;
    const TAKE_N: usize = 3;
    const FILE: &str = include_str!("../data/file_2.txt");
    let data = <Vec<u8>>::try_from_base64(FILE.replace("\n", "").as_ref())?;
    let keysizes = repeated_xor::find_best_keysize(&data, TAKE_N);
    utils::require(
        keysizes.contains(&EXPECTED),
        &format!("keysizes {:?} does not contain {}", keysizes, EXPECTED),
    )
}

fn challenge_7() -> Result<(), anyhow::Error> {
    const EXPECTED: &str = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
    const TAKE_N: usize = 3;
    const FILE: &str = include_str!("../data/file_2.txt");
    let data = <Vec<u8>>::try_from_base64(FILE.replace("\n", "").as_ref())?;
    let keys = repeated_xor::try_break(&data, repeated_xor::find_best_keysize(&data, TAKE_N));
    let decrypted = repeated_xor::try_break_encryption(&data, keys);
    utils::require_eq(decrypted.as_str(), EXPECTED)
}

fn challenge_8() -> Result<(), anyhow::Error> {
    pub fn count_identical_chunks(data: &[u8]) -> u32 {
        let mut count = 0;
        data.chunks(16).for_each(|chunk| {
            if data.chunks(16).filter(|n| *n == chunk).count() > 1 {
                count += 1
            }
        });
        count
    }

    const DATA: &str = include_str!("../data/challenge_8.txt");
    // KEY SIZE under AES-128 is always 16 bytes (16 * 8 = 128 bits)
    const KEY_SIZE: usize = 16;
    const EXPECTED: usize = 132;

    let data = Vec::<Vec<u8>>::try_from_hex(DATA)?;
    let similar_counts = data
        .iter()
        .enumerate()
        .map(|(index, item)| {
            (
                index,
                count_identical_chunks(item.as_slice() as &[u8]) as usize,
            )
        })
        .filter(|(_, count)| *count > 1)
        .collect::<Vec<_>>();

    let most_similar_index = similar_counts
        .iter()
        .max_by(|(_, left), (_, right)| left.cmp(right))
        .ok_or(anyhow!("no result"))?
        .0;

    utils::require_eq(most_similar_index, EXPECTED)
}

fn challenge_10() -> Result<(), anyhow::Error> {
    const DATA: &str = include_str!("../data/challenge_10.txt");
    const EXPECTED: &str = include_str!("../data/challlenge_10_expected.txt");
    const KEY: &[u8; 16] = b"YELLOW SUBMARINE";
    const IV: &[u8; 16] = b"0000000000000000";

    // Remove new lines and hex decode data.
    let data_line = DATA.lines().collect::<String>();
    let data = STANDARD
        .decode(data_line)
        .map_err(|_| anyhow!("Failed to decode base64"))?;
    // CDC decrypt encrypted data
    let mut iv = *IV;
    let result = crate::aes_128::decrypt_aes128_cbc(&data, KEY, &mut iv)
        .map_err(|_| anyhow!("Failed to decrypt AES-128 CBC"))?;
    let string_result = String::from_utf8_lossy(&result);
    // Create similarity_count to test result, if similarity_count is over 50, result should be
    // satisfactory.
    let mut similarity_count = 0;
    for word in string_result.split_ascii_whitespace() {
        if EXPECTED.contains(word) {
            similarity_count += 1
        }
    }
    if similarity_count < 50 {
        return Err(anyhow!(
            "unexpected result, similarity_count: {:?}",
            similarity_count
        ));
    }
    Ok(())
}
fn challenge_11() -> Result<(), anyhow::Error> {
    //Encrypt using a random key, append 5-10 bytes(count chosen randomly) before and after the
    //plaintext. use ECB 1/2 of the time, use CBC the other half(using random IV's).
    fn random_encryption<const BYTES: usize>(data: &[u8]) -> (&str, Vec<u8>) {
        //Add random bytes before and after the plaintext.
        let mut plaintext = utils::random_byte_vec();
        plaintext.extend_from_slice(data);
        plaintext.extend_from_slice(&utils::random_byte_vec());
        //Generate random 16 byte key and iv,
        let key = utils::generate_16_byte_key();
        let mut iv = utils::generate_16_byte_key();
        //encrypt chunks with random encryption method. returning encryption method so we can check our
        //result when testing the method detection function.
        match rand::rng().random_range(0..2) {
            1 => ("ebc", aes_128::encrypt_aes128_ecb(data, &key).unwrap()),
            _ => (
                "cbc",
                aes_128::encrypt_aes128_cbc(data, &key, &mut iv).unwrap(),
            ),
        }
    }
    const DATA: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let (expected, cipher) = random_encryption::<16>(DATA.as_bytes());
    //This detection mode only works when the encrypted plaintext is a string of identical bytes.
    //Because ebc uses a the same key to encrypt each block, the amound of identical bytes in the
    //ciphertext will be significantly higher. This means when we add every byte to a hashmap, the
    //length of the hashmap will be shorter for ebc mode.
    let mut counts = HashMap::new();
    for byte in &cipher {
        *counts.entry(byte).or_insert(0) += 1;
    }
    let uniqueness: f64 = (counts.len() as f64) / (cipher.len() as f64);
    println!("uniqueness: {uniqueness}, mode: {expected}");
    if uniqueness < 0.8 {
        assert_eq!(expected, "ebc");
    } else {
        assert_eq!(expected, "cbc")
    }
    Ok(())
}

fn challenge_12() -> Result<(), anyhow::Error> {
    const HEXSTRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    const TEST_STRING: &[u8] = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let key: Vec<u8> = vec![
        119, 120, 57, 66, 93, 72, 89, 114, 103, 91, 105, 56, 79, 51, 84, 80,
    ];
    const EXPECTED: &str = "Rollin' in my 5.0. With my rag-top down so my hair can blow. The girlies on standby waving just to say hi. Did you stop? No, I just drove by";

    // Oracle function that enctypts buffers under ECB mode using a consistent but unknown key. Before
    // decrypting the base64 decoded unknown string gets appended to the plaintext.
    // Function should produce: AES-128-ECB(your-string || unknown-string, random-key)
    fn challenge_12_oracle(unknown_string: &[u8], data: &[u8], key: &[u8]) -> Vec<u8> {
        //Append unknown string to plaintext
        let mut plaintext = data.to_vec();
        plaintext.extend_from_slice(unknown_string);

        //encrypt using ecb mode
        aes_128::encrypt_aes128_ecb(&plaintext, key).unwrap()
    }

    //This detection mode only works when the encrypted plaintext is a string of identical bytes.
    //Because ebc uses a the same key to encrypt each block, the amound of identical bytes in the
    //ciphertext will be significantly higher. This means when we add every byte to a hashmap, the
    //length of the hashmap will be shorter for ebc mode.
    fn detect_encryption_mode(cipher: Vec<u8>) -> String {
        let mut counts = HashMap::new();
        for byte in &cipher {
            *counts.entry(byte).or_insert(0) += 1;
        }
        let uniqueness: f64 = (counts.len() as f64) / (cipher.len() as f64);
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
        let initial_len = challenge_12_oracle(&[b'A'; 2], &[b'A'; 2], key).len();
        (2..64)
            .find_map(|x| {
                let input_bytes = vec![b'A'; x];
                let current_len = challenge_12_oracle(&[b'A'; 2], &input_bytes, key).len();
                let diff = current_len - initial_len;
                if diff > 1 { Some(x + 2) } else { None }
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
                let encrypted_k = challenge_12_oracle(&k, &k, key);
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

    // Detecting block size, then checking if the detection works.
    let blocksize = determine_block_size(&key);
    assert_eq!(blocksize, 16);

    // Detecting enctyption mode, then checking if detection works.
    let detection_cipher = challenge_12_oracle(&unknown_string, TEST_STRING, &key);
    let detected_mode = detect_encryption_mode(detection_cipher);
    assert_eq!("ebc", detected_mode);

    // Generate byte dictionary and short string. We will use this to try break the encryption.
    let byte_dictionary = generate_byte_dictionary(&key);
    let short_string = (0..15).map(|_| b'A').collect::<Vec<u8>>();

    // We will append the unknown string to the short string, resulting in a block with 15 known bytes,
    // and the first byte of the unknown string.
    let result: Vec<String> = (0..unknown_string.len())
        .filter_map(|x| {
            let first_block =
                challenge_12_oracle(&unknown_string[x..], &short_string, &key)[0..16].to_vec();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_1() -> Result<(), anyhow::Error> {
        challenge_1()
    }

    #[test]
    fn test_challenge_2() -> Result<(), anyhow::Error> {
        challenge_2()
    }

    #[test]
    fn test_challenge_3() -> Result<(), anyhow::Error> {
        challenge_3()
    }

    #[test]
    fn test_challenge_4() -> Result<(), anyhow::Error> {
        challenge_4()
    }

    #[test]
    fn test_challenge_5() -> Result<(), anyhow::Error> {
        challenge_5()
    }

    #[test]
    fn test_challenge_6() -> Result<(), anyhow::Error> {
        challenge_6()
    }

    #[test]
    fn test_challenge_7() -> Result<(), anyhow::Error> {
        challenge_7()
    }

    #[test]
    fn test_challenge_8() -> Result<(), anyhow::Error> {
        challenge_8()
    }

    #[test]
    fn challenge_10_test() -> Result<(), anyhow::Error> {
        challenge_10()
    }

    #[test]
    fn challenge_11_test() -> Result<(), anyhow::Error> {
        challenge_11()
    }
    #[test]
    fn challenge_12_test() -> Result<(), anyhow::Error> {
        challenge_12()
    }
}
