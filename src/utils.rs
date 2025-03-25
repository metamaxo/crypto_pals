#![allow(dead_code, unused_imports)]
use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose};

pub fn bytes_xor(left: &[u8], right: &[u8]) -> Vec<u8> {
    left.iter()
        .zip(right.iter().cycle())
        .map(|(l, r)| l ^ r)
        .collect()
}

pub fn compute_hamming(left: u8, right: u8) -> u32 {
    let xored = left ^ right;
    xored.count_ones()
}
pub fn slice_hamming(left: &[u8], right: &[u8]) -> u32 {
    left.iter()
        .zip(right)
        .map(|(left, right)| compute_hamming(*left, *right))
        .sum()
}

#[test]
fn test_slice_hamming() -> Result<(), anyhow::Error> {
    const FILE: &str = "this is a test";
    const RIGHT: &str = "wokka wokka!!!";
    const EXPECTED: u32 = 37;
    let hemming = crate::utils::slice_hamming(FILE.as_bytes(), RIGHT.as_bytes());
    if hemming != EXPECTED {
        return Err(anyhow!("unexpected result"));
    }
    Ok(())
}

pub fn alphabet_index(c: char) -> usize {
    match c {
        c @ 'A'..='Z' => (c as usize) - 65,
        c @ 'a'..='z' => (c as usize) - 97,
        ' ' => 26,
        _ => 27,
    }
}

pub fn character_count(input: &str) -> [usize; 28] {
    input.chars().fold([0; 28], |mut acc, char| {
        acc[alphabet_index(char)] += 1;
        acc
    })
}

pub fn character_frequency_map(input: &str) -> [f32; 28] {
    character_count(input)
        .into_iter()
        .map(|count| (count as f32) / (input.len() as f32))
        .collect::<Vec<f32>>()
        .try_into()
        .unwrap_or_default()
}

const LETTER_FREQ: [f32; 28] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.19181, 0.00000, // V-Z & space char & other
];

pub fn english_index_expected_frequency(i: usize) -> f32 {
    LETTER_FREQ.get(i).copied().unwrap_or_default()
}

pub fn english_character_expected_frequency(c: char) -> f32 {
    const UPPERCASE_DISCOUNT: f32 = 0.99;
    let scalar = match c {
        c if c.is_uppercase() => UPPERCASE_DISCOUNT,
        _ => 1.0,
    };
    english_index_expected_frequency(alphabet_index(c)) * scalar
}

pub fn english_score_bytes(input: &[u8]) -> f32 {
    english_score_str(&String::from_utf8_lossy(input))
}

pub fn score_frequency_map(freq_map: &[f32; 28]) -> f32 {
    fn compare_freq((x, y): (&f32, &f32)) -> f32 {
        (*y - *x).powi(2)
    }
    freq_map
        .iter()
        .zip(LETTER_FREQ.iter())
        .map(compare_freq)
        .sum::<f32>()
}

pub fn english_score_str(input: &str) -> f32 {
    score_frequency_map(&character_frequency_map(input))
}

#[test]
pub fn test_english_frequency() -> Result<(), anyhow::Error> {
    const SHORT_ENGLISH: &str = "hello";
    const LONG_GIBBERISH: &str = "djkaf;dskaj;eolajek;auipubiaujdfai;jea'rejajreiahgkda;jbkfjakdlfja;jeklwq;urti32u5iou643612j3jlkdja; ekjalek;jke;ajreial;rejk";

    let short_english_score = english_score_str(SHORT_ENGLISH);
    let long_gibberish_score = english_score_str(LONG_GIBBERISH);

    if short_english_score < long_gibberish_score {
        return Err(anyhow!("unexpected result"));
    }
    Ok(())
}
