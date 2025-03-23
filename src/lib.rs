#[allow(unused_imports)]
use anyhow::anyhow;
mod repeated_xor;
mod single_byte_xor;
mod utils;
use base64::{Engine as _, engine::general_purpose};

pub fn hex_to_base64(data: String) -> Result<String, anyhow::Error> {
    hex::decode(data)
        .map_err(|e| e.into())
        .map(|bytes| general_purpose::STANDARD.encode(&bytes))
}

#[test]
fn test_1() -> Result<(), anyhow::Error> {
    const INPUT: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const EXPECTED: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    if hex_to_base64(INPUT.to_string())? != EXPECTED {
        return Err(anyhow!("unexpected result"));
    }
    Ok(())
}

#[test]
fn test_2() -> Result<(), anyhow::Error> {
    const INPUT: &str = "1c0111001f010100061a024b53535009181c";
    const BUFFER: &str = "686974207468652062756c6c277320657965";
    const EXPECTED: &str = "746865206b696420646f6e277420706c6179";
    let result = hex::encode(utils::bytes_xor(
        &hex::decode(INPUT).unwrap(),
        &hex::decode(BUFFER).unwrap(),
    ));
    if result != EXPECTED {
        return Err(anyhow!("unexpected result"));
    }
    Ok(())
}

#[test]
fn test_3() -> Result<(), anyhow::Error> {
    const INPUT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const EXPECTED: u8 = 88;
    let input_bytes = hex::decode(INPUT)?;
    let result = single_byte_xor::try_break(&input_bytes).ok_or(anyhow!("no result"))?;
    if result.byte as u8 != EXPECTED {
        return Err(anyhow!("expected {} got {}", EXPECTED, result.byte));
    }
    Ok(())
}
fn parse_file_lines(input: &str) -> Result<Vec<Vec<u8>>, anyhow::Error> {
    Ok(input
        .lines()
        .map(str::trim)
        .map(hex::decode)
        .collect::<Result<_, _>>()?)
}

#[test]
fn test_4() -> Result<(), anyhow::Error> {
    const FILE: &str = include_str!("../data/file_1.txt");
    const EXPECTED: &str = "Now that the party is jumping\n";
    let lines = parse_file_lines(FILE)?;

    let Some((line, result)) = lines
        .iter()
        .zip(
            lines
                .iter()
                .map(|line| single_byte_xor::try_break(line.as_slice())),
        )
        .flat_map(|(line, result)| result.map(|result| (line, result)))
        .min_by(|(_, left_result), (_, right_result)| left_result.cmp(right_result))
    else {
        return Err(anyhow!("no result"));
    };

    let s = String::from_utf8_lossy(&utils::bytes_xor(line, &[result.byte])).to_string();

    if s != EXPECTED {
        return Err(anyhow!("expected {} got {:?}", EXPECTED, s));
    };
    Ok(())
}

#[test]
fn test_5() -> Result<(), anyhow::Error> {
    const FILE: &str = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    const EXPECTED: &str =
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    const KEY: &str = "ICE";
    let file_lines: Vec<Vec<u8>> = FILE.lines().map(|line| line.as_bytes().to_vec()).collect();
    let expected_lines: Vec<Vec<u8>> = EXPECTED.lines().flat_map(hex::decode).collect();
    for (line, expected) in file_lines.iter().zip(expected_lines) {
        if utils::bytes_xor(line, KEY.as_bytes()) != expected {
            return Err(anyhow!("unexpected result"));
        }
    }
    Ok(())
}

#[test]
fn test_6() -> Result<(), anyhow::Error> {
    Ok(())
}
