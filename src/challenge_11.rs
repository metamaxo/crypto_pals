//Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

//The function should look like:

//encryption_oracle(your-input)
//=> [MEANINGLESS JIBBER JABBER]

//Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

//Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

//Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
use crate::repeated_xor;
use crate::utils;
use anyhow::anyhow;
use rand::Rng;
use std::collections::HashMap;

use crate::aes_128::{self, encrypt_aes128_cbc, encrypt_aes128_ecb};

fn challenge_11(data: &[u8]) {
    //Encrypt using a random key, append 5-10 bytes(count chosen randomly) before and after the
    //plaintext. use ECB 1/2 of the time, use CBC the other half(using random IV's).
    fn random_encryption<const BYTES: usize>(data: &[u8]) -> (&str, Vec<u8>) {
        //Add random bytes before and after the plaintext.
        let mut plaintext = utils::random_byte_vec();
        plaintext.extend_from_slice(data);
        plaintext.extend_from_slice(&utils::random_byte_vec());
        //Generate random 16 byte key and iv,
        let key = utils::generate_16_byte_key();
        println!("key is: {:?}", key);
        let mut iv = utils::generate_16_byte_key();
        //encrypt chunks with random encryption method. returning encryption method so we can check our
        //result when testing the method detection function.
        match rand::rng().random_range(0..2) {
            1 => ("ebc", encrypt_aes128_ecb(data, &key).unwrap()),
            _ => ("cbc", encrypt_aes128_cbc(data, &key, &mut iv).unwrap()),
        }
    }

    let (expected, cipher) = random_encryption::<16>(data);
    //This detection mode only works when the encrypted plaintext is a string of identical bytes.
    //Because ebc uses a the same key to encrypt each block, the amound of identical bytes in the
    //ciphertext will be significantly higher. This means when we add every byte to a hashmap, the
    //length of the hashmap will be shorter for ebc mode.
    let mut counts = HashMap::new();
    for byte in cipher {
        *counts.entry(byte).or_insert(0) += 1;
    }
    let uniqueness: f64 = (counts.len() as f64) / (data.len() as f64);
    if uniqueness < 0.8 {
        assert_eq!(expected, "ebc");
    }

    assert_eq!(expected, "cbc")
}

#[test]
fn find_encryption_mode_test() {
    const DATA: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    challenge_11(DATA.as_bytes());
}
