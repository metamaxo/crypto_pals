use crate::aes_128;
use crate::aes_128::encrypt_aes128;
use crate::repeated_xor;
use crate::traits::{
    BytesBase64Ext, BytesExt, BytesHexExt, BytesHexLinesExt, BytesStrExt, BytesStrLinesExt as _,
};
use anyhow::anyhow;
use itertools::Itertools;
use std::collections::HashMap;

fn find_similar_chunks(data: &[u8]) -> u32 {
    let mut count = 0;
    data.chunks(4).for_each(|chunk| {
        if data.chunks(4).filter(|n| *n == chunk).count() > 1 {
            count += 1
        }
    });
    count
}

#[test]
fn challenge_8_test() -> Result<(), anyhow::Error> {
    const DATA: &str = include_str!("../data/challenge_8.txt");
    const EXPECTED: usize = 132;
    let data = Vec::<Vec<u8>>::try_from_hex(DATA)?;
    let mut result = 0;
    for (index, item) in data.iter().enumerate() {
        if find_similar_chunks(item) > 1 {
            result = index;
        }
    }
    if result != EXPECTED {
        return Err(anyhow!("unexpected result!"));
    }
    Ok(())
}
