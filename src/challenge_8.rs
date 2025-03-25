use std::collections::HashMap;

use crate::repeated_xor;
use crate::traits::{
    BytesBase64Ext, BytesExt, BytesHexExt, BytesHexLinesExt as _, BytesStrExt,
    BytesStrLinesExt as _,
};
use anyhow::anyhow;
//TODO
//File = hex-encoded-cyphertexts
//one has been encrypted with ECB
//Find it
//trying to get the keysize by parsing over strings, no clear results yet.
//trying a different approach tomorrow
#[test]
fn challenge_9() -> Result<(), anyhow::Error> {
    const FILE: &str = include_str!("../data/challenge_8.txt");
    const TAKE_N: usize = 3;
    let data_strings = Vec::<Vec<u8>>::try_from_hex(FILE).unwrap();
    println!("hex succes");
    let mut keysize_list = HashMap::new();
    for string in data_strings {
        let keysizes = repeated_xor::find_best_keysize(&string, TAKE_N);
        for keysize in keysizes {
            let counter = keysize_list.entry(keysize).or_insert(0);
            *counter += 1
        }
    }
    let top_key = keysize_list.iter().max_by(|a, b| a.1.cmp(&b.1)).unwrap();
    println!(
        "all found keysizes: {:?}, top match: {:?}",
        keysize_list, top_key
    );

    Ok(())
}
