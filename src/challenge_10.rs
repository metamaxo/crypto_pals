use crate::aes_128;
use crate::utils;
use anyhow::Error;
use anyhow::anyhow;

fn challenge_10() -> Result<(), anyhow::Error> {
    const DATA: &str = include_str!("../data/challenge_10.txt");
    const KEY: &str = "YELLOW SUBMARINE";
    let result = aes_128::decrypt_aes128_cbc_mode(DATA.as_bytes(), KEY.as_bytes())?;
    println!("{:?}", String::from_utf8_lossy(&result));

    Ok(())
}

#[test]
fn challenge_10_test() -> Result<(), anyhow::Error> {
    challenge_10()
}
