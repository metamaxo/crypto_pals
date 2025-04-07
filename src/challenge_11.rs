//Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

//The function should look like:

//encryption_oracle(your-input)
//=> [MEANINGLESS JIBBER JABBER]

//Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

//Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

//Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.

use anyhow::anyhow;
use rand::Rng;

use crate::aes_128::{self, encrypt_aes128_cbc, encrypt_aes128_ecb};

fn random_byte_vec() -> Vec<u8> {
    (0..rand::rng().random_range(5..10))
        .map(|_| random_byte())
        .collect()
}

fn random_byte() -> u8 {
    rand::rng().random_range(33..126) as u8
}

fn generate_16_byte_key() -> Vec<u8> {
    (0..16).map(|_| random_byte()).collect::<Vec<u8>>()
}
//Encrypt using a random key, append 5-10 bytes(count chosen randomly) before and after the
//plaintext. use ECB 1/2 of the time, use CBC the other half(using random IV's).
fn encrypt_with_random_key<const BYTES: usize>(data: &[u8]) -> (&str, Vec<u8>) {
    //Add random bytes before and after the plaintext.
    let mut plaintext = random_byte_vec();
    plaintext.extend_from_slice(data);
    plaintext.extend_from_slice(&random_byte_vec());
    //Generate random 16 byte key and iv,
    let key = generate_16_byte_key();
    let mut iv = generate_16_byte_key();
    //encrypt chunks with random encryption method. returning encryption method so we can check our
    //result when testing the method detection function.
    match rand::rng().random_range(0..2) {
        1 => ("ebc", encrypt_aes128_ecb(data, &key).unwrap()),
        _ => ("cbc", encrypt_aes128_cbc(data, &key, &mut iv).unwrap()),
    }
}

#[test]
fn generate_key_test() {
    const EXCEPTED_LENGTH: usize = 16;
    let key = generate_16_byte_key();
    println!("{:?}", String::from_utf8_lossy(&key));
    assert_eq!(key.len(), EXCEPTED_LENGTH);
}
#[test]
fn encrypt_with_random_key_test() -> Result<(), anyhow::Error> {
    const DATA: &str = include_str!("../data/lorem_ipsum.txt");
    let mut cbc = 0;
    let mut ebc = 0;
    let mut bad_result = 0;
    for _ in 0..10 {
        let (method, _) = encrypt_with_random_key::<16>(DATA.as_bytes());
        match method {
            "ebc" => ebc += 1,
            "cbc" => cbc += 1,
            _ => bad_result += 1,
        }
    }
    if bad_result > 0 {
        return Err(anyhow!("unknown method!"));
    }
    if ebc == 0 || cbc == 0 {
        return Err(anyhow!("uneven result!"));
    }
    Ok(())
}
