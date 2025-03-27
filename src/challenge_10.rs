use crate::aes_128;
use crate::repeated_xor;
use crate::single_byte_xor;
use crate::utils;

//todo
//CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite
//the fact that a block cipher natively only transforms individual blocks.
//
//in CBC mode each ciphertext block is added to the next plaintext block before the next call to
//cipher core.
//
//the first plaintext block which has no associated previous ciphertext block, is added to a "fake
//0th ciphertext block" called the initialization vector, or IV.
//
//implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt
//instead of decrypt and using your XOR function from the previous exercise to combine them.
//
//verify the encrypt function by decrypting whatever you encrypt to test.
//
//the file, saved in data is intelligeble when decrypted against yellow submarine with an IV of
//all ASCII 0 (\x00\x00\x00 &c)

// fn cbc_mode_encrypt(data: &[u8], key: &[u8]) Result<(), error::anyhow {
//     //creating initialization vector of all ASCII 0
//     let mut iv: Vec<u8> = Vec::with_capacity(16);
//     iv.extend_from_slice(&[0u8; 16]);
//     println!("{:?}", iv);
//     //make blocks of 16 bytes
//     let blocks = data.chunks_exact(16);
//     //xor iv with first block, then encrypt it with key
//     let initial_block = utils::bytes_xor(blocks.next()?, iv);
//     let encrypted_block = aes_128::encrypt(t, key, iv, data)
//     //now xor each
//
//     OK(())
// }
//
// #[test]
// fn cbc_mode_encrypt_test() {
//     const DATA: &str = include_str!("../data/lorem_ipsum.txt");
//     const KEY: &[u8] = b"YELLOW SUBMARINE";
//     cbc_mode_encrypt(DATA.as_bytes(), KEY);
// }
