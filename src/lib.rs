#![allow(dead_code, unused_imports)]
mod aes_128;
mod challenge_8;
mod repeated_xor;
mod single_byte_xor;
mod traits;
mod types;
mod utils;

use traits::{
    BytesBase64Ext, BytesExt, BytesHexExt, BytesHexLinesExt as _, BytesStrExt,
    BytesStrLinesExt as _,
};

use ::anyhow::anyhow;
use base64::{engine as _, engine::general_purpose};

fn challenge_1() -> Result<(), anyhow::Error> {
    const INPUT: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const EXPECTED: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    utils::require_eq(
        <Vec<u8>>::try_from_hex(INPUT)?.to_base64().as_str(),
        EXPECTED,
    )
}

fn challenge_2() -> Result<(), anyhow::Error> {
    const INPUT: &str = "1c0111001f010100061a024b53535009181c";
    const BUFFER: &str = "686974207468652062756c6c277320657965";
    const EXPECTED: &str = "746865206b696420646f6e277420706c6179";

    let result = utils::bytes_xor(
        &<Vec<u8>>::try_from_hex(INPUT)?,
        &<Vec<u8>>::try_from_hex(BUFFER)?,
    )
    .to_hex();
    utils::require_eq(result.as_str(), EXPECTED)
}

fn challenge_3() -> Result<(), anyhow::Error> {
    const INPUT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const EXPECTED: u8 = 88;
    let result =
        single_byte_xor::try_break(&<Vec<u8>>::try_from_hex(INPUT)?).ok_or(anyhow!("no result"))?;
    utils::require_eq(result.byte, EXPECTED)
}

fn challenge_4() -> Result<(), anyhow::Error> {
    const FILE: &str = include_str!("../data/file_1.txt");
    const EXPECTED: &str = "Now that the party is jumping\n";
    let lines = <Vec<Vec<u8>>>::try_from_hex(FILE)?;

    let Some((line, result)) = lines
        .iter()
        .zip(lines.iter().map(|line| single_byte_xor::try_break(line)))
        .flat_map(|(line, result)| result.map(|result| (line, result)))
        .min_by(|(_, left_result), (_, right_result)| left_result.cmp(right_result))
    else {
        return Err(anyhow!("no result"));
    };

    let s = String::from_utf8_lossy(&utils::bytes_xor(line, &[result.byte])).to_string();
    utils::require_eq(s.as_str(), EXPECTED)
}

fn challenge_5() -> Result<(), anyhow::Error> {
    const FILE: &str =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const EXPECTED: &str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    const KEY: &str = "ICE";

    let file = <Vec<u8>>::from_str(FILE);
    let expected_lines = <Vec<u8>>::try_from_hex(EXPECTED)?;

    let key = KEY.as_bytes();
    let decrypted = utils::bytes_xor(&file, key);
    utils::require_eq(decrypted, expected_lines)
}

fn challenge_6() -> Result<(), anyhow::Error> {
    const EXPECTED: u32 = 18;
    const TAKE_N: usize = 3;
    const FILE: &str = include_str!("../data/file_2.txt");
    let data = <Vec<u8>>::try_from_base64(FILE.replace("\n", "").as_ref())?;
    let keysizes = repeated_xor::find_best_keysize(&data, TAKE_N);
    utils::require(
        keysizes.contains(&EXPECTED),
        &format!("keysizes {:?} does not contain {}", keysizes, EXPECTED),
    )
}

fn challenge_7() -> Result<(), anyhow::Error> {
    const EXPECTED: &str = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
    const TAKE_N: usize = 3;
    const FILE: &str = include_str!("../data/file_2.txt");
    let data = <Vec<u8>>::try_from_base64(FILE.replace("\n", "").as_ref())?;
    let keys = repeated_xor::try_break(&data, repeated_xor::find_best_keysize(&data, TAKE_N));
    let decrypted = repeated_xor::try_break_encryption(&data, keys);
    utils::require_eq(decrypted.as_str(), EXPECTED)
}

fn challenge_8() -> Result<(), anyhow::Error> {
    const KEY: &str = "YELLOW SUBMARINE";
    const FILE: &str = include_str!("../data/challenge_7_data.txt");
    const EXPECTED: &str = include_str!("../data/challenge_7_expected.txt");
    let data = Vec::try_from_base64(FILE.replace("\n", "").as_ref())?;
    let decrypted_bytes = aes_128::decrypt_aes128(&data, KEY.as_bytes())?;
    let result = String::from_utf8_lossy(&decrypted_bytes);
    utils::require_eq(&result[1..20], &EXPECTED[1..20])
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_1() -> Result<(), anyhow::Error> {
        challenge_1()
    }

    #[test]
    fn test_challenge_2() -> Result<(), anyhow::Error> {
        challenge_2()
    }

    #[test]
    fn test_challenge_3() -> Result<(), anyhow::Error> {
        challenge_3()
    }

    #[test]
    fn test_challenge_4() -> Result<(), anyhow::Error> {
        challenge_4()
    }

    #[test]
    fn test_challenge_5() -> Result<(), anyhow::Error> {
        challenge_5()
    }

    #[test]
    fn test_challenge_6() -> Result<(), anyhow::Error> {
        challenge_6()
    }

    #[test]
    fn test_challenge_7() -> Result<(), anyhow::Error> {
        challenge_7()
    }

    #[test]
    fn test_challenge_8() -> Result<(), anyhow::Error> {
        challenge_8()
    }
}
