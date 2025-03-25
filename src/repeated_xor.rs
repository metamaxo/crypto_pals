#![allow(dead_code, unused_imports)]
use crate::{
    single_byte_xor::{self, BreakResult},
    utils,
};
use anyhow::anyhow;
use std::slice;

pub fn keysize_scores(data: &[u8]) -> Vec<(u32, f32)> {
    const MAX_KEYSIZE: u32 = 40;
    let mut results = Vec::new();
    for k in 2..MAX_KEYSIZE.min(data.len() as u32 / 2) {
        let chunks: Vec<Vec<u8>> = data
            .chunks_exact(k as usize)
            .map(|chunk| chunk.to_vec())
            .collect();

        let scores = chunks
            .iter()
            .enumerate()
            .flat_map(|(i, left)| {
                chunks
                    .iter()
                    .skip(i + 1)
                    .map(|right| utils::slice_hamming(left, right))
            })
            .collect::<Vec<u32>>();

        let total_score = scores.iter().sum::<u32>();
        let normalized_score = (total_score as f32) / (k as f32) / (scores.len() as f32);
        results.push((k, normalized_score));
    }
    results
}

pub fn find_best_keysize(data: &[u8], take_n: usize) -> Vec<u32> {
    fn sort_by_score(a: &(u32, f32), b: &(u32, f32)) -> std::cmp::Ordering {
        match a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal) {
            std::cmp::Ordering::Equal => a.0.cmp(&b.0),
            other => other,
        }
    }
    let mut scores = keysize_scores(data);
    scores.sort_by(sort_by_score);
    let mut best_keysizes: Vec<u32> = scores.into_iter().take(take_n).map(|v| v.0).collect();
    best_keysizes.sort();
    best_keysizes
}

pub fn try_break(data: &[u8], keysize: Vec<u32>) -> Vec<(u32, Vec<u8>)> {
    let keys: Vec<(u32, Vec<u8>)> = keysize
        .iter()
        .map(|&size| {
            let key: Vec<u8> = (0..size)
                .map(|t| {
                    let bits: Vec<u8> = data
                        .chunks_exact(size as usize)
                        .filter_map(|chunk| chunk.get(t as usize).cloned())
                        .collect();
                    single_byte_xor::try_break(&bits).unwrap().byte
                })
                .collect();
            (size, key)
        })
        .collect();
    keys
}

pub fn try_break_encryption(data: &[u8], keys: Vec<(u32, Vec<u8>)>) -> String {
    let mut decrypted_list: Vec<(f32, Vec<u8>)> = keys
        .into_iter()
        .map(|(_, key)| {
            let result = utils::bytes_xor(data, &key);
            let score = utils::english_score_bytes(&result);
            (score, result)
        })
        .collect();
    decrypted_list.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    String::from_utf8_lossy(decrypted_list.first().unwrap().1.as_ref()).to_string()
}

#[test]
fn try_break_test() -> Result<(), anyhow::Error> {
    fn generate_test_key_bytes(n: u32) -> Vec<u8> {
        // const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..n).map(|_| rand::random::<u8>()).collect()
    }
    const TEST_STRING: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer ultricies suscipit mauris eget fringilla. Mauris eget congue nisi, in mattis tellus. Quisque eu leo ornare, pretium magna at, consequat diam. Nulla id massa elit. Donec et arcu nisi. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Suspendisse eu turpis tempus, luctus elit at, aliquet ex.
Maecenas porttitor posuere ipsum sit amet suscipit. Donec nibh magna, hendrerit nec hendrerit at, imperdiet et arcu. Vestibulum ac augue id ex fermentum lobortis. Suspendisse maximus velit eu felis pellentesque, efficitur egestas lacus pulvinar. Phasellus faucibus euismod erat id blandit. Phasellus feugiat finibus justo sit amet tincidunt. Maecenas erat arcu, molestie nec auctor vel, commodo nec odio. Suspendisse potenti. Quisque hendrerit, justo non blandit molestie, ligula ligula tristique mauris, nec sollicitudin est neque quis leo. Mauris in turpis ut diam dictum vulputate.
Curabitur sed lobortis turpis. Integer in urna tincidunt, sollicitudin neque id, condimentum tellus. Aliquam luctus felis vel eros ullamcorper lobortis. Vivamus semper, felis sed volutpat ornare, nisi quam venenatis nisl, sed dictum enim magna sed sapien. Pellentesque viverra, massa eget fermentum laoreet, odio libero auctor felis, non accumsan odio erat vitae ligula. Sed in consequat tellus. Mauris eu suscipit dui.
Duis euismod, eros nec posuere pulvinar, tellus enim hendrerit sapien, id viverra nulla enim vitae velit. Cras hendrerit luctus leo eu ultrices. Donec convallis urna sollicitudin maximus dignissim. Vivamus dignissim libero vel interdum tincidunt. Nunc convallis elit et dui faucibus, ut tincidunt est mattis. Sed id hendrerit enim. Nunc vel faucibus magna. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Aenean in auctor arcu. Cras quis sem et ex aliquam porta non venenatis tortor.
Suspendisse potenti. Aliquam porta lorem ut porta venenatis. Donec ut scelerisque eros, at euismod enim. Curabitur nec quam lorem. Morbi placerat vel diam nec auctor. Mauris arcu diam, pulvinar a fringilla non, lacinia ut erat. Suspendisse potenti. Donec faucibus pretium faucibus. Cras fermentum magna eget leo egestas, sit amet interdum magna laoreet. Phasellus eget odio eget massa interdum aliquam sit amet sit amet odio. Sed lacinia, sapien eget consectetur commodo, nunc orci tempor libero, eu volutpat turpis arcu non quam. Curabitur fermentum tincidunt lorem, vitae faucibus est rhoncus ultrices. Duis quis nisl ac nibh finibus accumsan.";
    const MIN_KEYSIZE: u32 = 10;
    const MAX_KEYSIZE: u32 = 40;
    const TAKE_N: usize = 3;

    const ALLOWED_MISSES: usize = 3;

    let mut miss_count = 0;

    let test_string_bytes = TEST_STRING.as_bytes();
    for keysize in MIN_KEYSIZE..MAX_KEYSIZE {
        let test_key = generate_test_key_bytes(keysize);
        let encrypted = utils::bytes_xor(test_string_bytes, &test_key);
        let best_keysizes = find_best_keysize(&encrypted, TAKE_N);
        let found_keys = try_break(&encrypted, best_keysizes);
        let expected = (keysize, test_key);
        if !found_keys.contains(&expected) {
            miss_count += 1;
        }
    }
    utils::require(miss_count <= ALLOWED_MISSES, &format!("too many misses {}", miss_count))
}

#[test]
fn find_keysize_test() -> Result<(), anyhow::Error> {
    fn generate_test_key_bytes(n: u32) -> Vec<u8> {
        // const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..n).map(|_| rand::random::<u8>()).collect()
    }
    const TEST_STRING: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce quis malesuada nunc. Integer rutrum rutrum mi nec elementum. Vivamus gravida massa in ex blandit, quis consequat sem tempus. Nullam a finibus dolor, ut aliquet eros. Nullam fermentum scelerisque leo, vel euismod eros dapibus at. Proin eros odio, pharetra eu lobortis non, pulvinar et neque. Phasellus ornare, magna sit amet bibendum egestas, purus augue molestie libero, non aliquet felis quam a tellus. Aliquam fringilla a quam et gravida. Mauris a ullamcorper nibh, sed fringilla mi.";
    const MIN_KEYSIZE: u32 = 10;
    const MAX_KEYSIZE: u32 = 40;
    const MAX_ALLOWED_POSITION: usize = 3;

    let test_string_bytes = TEST_STRING.as_bytes();

    for keysize in MIN_KEYSIZE..MAX_KEYSIZE {
        let key = generate_test_key_bytes(keysize);
        let encrypted = utils::bytes_xor(test_string_bytes, &key);

        let mut scores = keysize_scores(&encrypted);
        scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        let found_at_position = scores.iter().position(|item| item.0 == keysize).unwrap();
        utils::require(
            found_at_position <= MAX_ALLOWED_POSITION,
            &format!(
                "keysize {} expected below position {} found at position {}",
                keysize,
                MAX_ALLOWED_POSITION,
                found_at_position,
            ),
        )?;
    }
    Ok(())
}
