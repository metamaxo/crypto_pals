use crate::aes_128;
use crate::traits::BytesBase64Ext;
use crate::traits::BytesHexExt;
use crate::utils;
use anyhow::Error;
use anyhow::anyhow;

use base64::{Engine, engine as _, engine::general_purpose::STANDARD};

fn challenge_10() -> Result<(), anyhow::Error> {
    const DATA: &str = include_str!("../data/challenge_10.txt");
    const KEY: &[u8; 16] = b"YELLOW SUBMARINE";
    const IV: &[u8; 16] = b"0000000000000000";

    let data_line = DATA.lines().collect::<String>();
    let data = STANDARD
        .decode(data_line)
        .map_err(|_| anyhow!("Failed to decode base64"))?;

    let mut iv = *IV;
    let result = crate::aes_128::decrypt_aes128_cbc(&data, KEY, &mut iv)
        .map_err(|_| anyhow!("Failed to decrypt AES-128 CBC"))?;
    let string_result = String::from_utf8_lossy(&result);

    println!("{:?}", string_result);

    Ok(())
}

#[test]
fn challenge_10_test() -> Result<(), anyhow::Error> {
    challenge_10()
}
