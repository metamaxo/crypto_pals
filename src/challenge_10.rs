use crate::aes_128;
use crate::traits::BytesBase64Ext;
use crate::traits::BytesHexExt;
use crate::utils;
use anyhow::Error;
use anyhow::anyhow;

fn challenge_10() -> Result<(), anyhow::Error> {
    const DATA: &str = include_str!("../data/challenge_10.txt");
    const KEY: &[u8] = b"YELLOW SUBMARINE";
    let data = <Vec<u8>>::try_from_base64(
        DATA.replace("\n", "")
            .replace("\r", "")
            .replace("\r\n", "")
            .as_ref(),
    )?;
    let result = aes_128::decrypt_aes128_cbc_mode(&data, KEY)?;
    let string_result = String::from_utf8_lossy(&result);

    println!("{:?}", string_result);

    Ok(())
}

#[test]
fn challenge_10_test() -> Result<(), anyhow::Error> {
    challenge_10()
}
