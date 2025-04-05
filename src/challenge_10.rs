use crate::aes_128;
use crate::traits::BytesBase64Ext;
use crate::traits::BytesHexExt;
use crate::utils;
use anyhow::Error;
use anyhow::anyhow;
use openssl::base64;

fn challenge_10() -> Result<(), anyhow::Error> {
    const DATA: &str = include_str!("../data/challenge_10.txt");
    const KEY: &[u8; 16] = b"YELLOW SUBMARINE";
    let data = base64::decode_block(
        DATA.replace("\n", "")
            .replace("\r", "")
            .replace("\r\n", "")
            .as_ref(),
    )?;
    let result = crate::aes::decrypt_cbc::<16>(&data, KEY, &mut [0u8; 16])?;
    let string_result = String::from_utf8_lossy(&result);

    println!("{:?}", string_result);

    Ok(())
}

#[test]
fn challenge_10_test() -> Result<(), anyhow::Error> {
    challenge_10()
}
