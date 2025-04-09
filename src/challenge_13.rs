use crate::{aes_128, utils::generate_16_byte_key};
use anyhow::{Error, anyhow};
use std::collections::HashMap;

// Parse a string of keys and values and procude a HashMap.
fn dict_from_string(data: &str) -> HashMap<String, String> {
    data.split("&") // pairs are divided by &
        .filter_map(|pair| {
            let parts: Vec<&str> = pair.split("=").collect(); // key and value is divided by =
            if parts.len() == 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                None
            }
        })
        .collect()
}

// Parse object and produce a string
fn string_from_dict(dict: HashMap<String, String>) -> String {
    dict.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<String>>()
        .join("&")
}

// Checks email length, if it ends with a top lever domain name and if it conains unwanted symbols
// before producing a profile object in string form.
fn profile_for(email_adress: &str) -> Result<String, anyhow::Error> {
    if email_adress.len() >= 4
        && email_adress[(email_adress.len() - 4)..(email_adress.len() - 2)].contains(".")
        && !email_adress.contains(['&', '='])
    {
        let profile = HashMap::from([
            ("email".to_string(), email_adress.to_string()),
            ("uid".to_string(), "10".to_string()),
            ("role".to_string(), "user".to_string()),
        ]);
        Ok(string_from_dict(profile))
    } else {
        Err(anyhow!("invalid email adress"))
    }
}

// The oracle produces an ecb encrypted profile.
fn profile_for_oracle(email: &str, key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    aes_128::encrypt_aes128_ecb(profile_for(email)?.as_bytes(), key)
}
// Decrypts the cipher and checks the current role.
fn oracle_role(cipher: &[u8], key: &[u8]) -> Result<String, anyhow::Error> {
    let plaintext = aes_128::decrypt_aes128_ecb(cipher, key)?;
    let dict = dict_from_string(String::from_utf8_lossy(&plaintext).as_ref());
    match dict.get("role") {
        Some(role) => Ok(role.to_string()),
        None => Err(anyhow!("role not found")),
    }
}

// Generate a random AES key.
// -Encrypt the encoded user profile under the key; "provide" that to the "attacker".
// -Decrypt the encoded user profile and parse it.
// Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
fn challenge_13() -> Result<(), anyhow::Error> {
    const USER_EMAIL: &str = "foo@bar.com";
    let key: Vec<u8> = vec![
        119, 120, 57, 66, 93, 72, 89, 114, 103, 91, 105, 56, 79, 51, 84, 80,
    ];
    // We get the encrypted profile from the oracle, now we have to change our role to admin.
    let cipher = profile_for_oracle(USER_EMAIL, &key)?;
    // We send the cipher back to the oracle and check our current role
    let role = oracle_role(&cipher, &key);
    println!("role: {:?}", role);
    Ok(())
}

#[test]
fn challenge_13_test() -> Result<(), anyhow::Error> {
    challenge_13()
}

#[test]
fn profile_for_test() -> Result<(), anyhow::Error> {
    const TEST_EMAIL_1: &str = "foo@bar.com";
    const TEST_EMAIL_2: &str = "foo=@bar.com";
    const TEST_EMAIL_3: &str = "foo@&bar.com";
    const TEST_EMAIL_4: &str = "foo@bar.com&role=admin";
    const TEST_EMAIL_5: &str = "foo@bar.co.uk";

    let expected: HashMap<String, String> = {
        let mut m = HashMap::new();
        m.insert("email".to_string(), "foo@bar.com".to_string());
        m.insert("role".to_string(), "user".to_string());
        m.insert("uid".to_string(), "10".to_string());
        m
    };
    assert_eq!(
        dict_from_string(&profile_for(TEST_EMAIL_1).unwrap()),
        expected
    );
    match profile_for(TEST_EMAIL_2) {
        Ok(unexpected_value) => panic!("Expected an Err, but got Ok({})", unexpected_value),
        Err(expected_error) => assert_eq!(expected_error.to_string(), "invalid email adress"),
    }
    match profile_for(TEST_EMAIL_3) {
        Ok(unexpected_value) => panic!("Expected an Err, but got Ok({})", unexpected_value),
        Err(expected_error) => assert_eq!(expected_error.to_string(), "invalid email adress"),
    }
    match profile_for(TEST_EMAIL_4) {
        Ok(unexpected_value) => panic!("Expected an Err, but got Ok({})", unexpected_value),
        Err(expected_error) => assert_eq!(expected_error.to_string(), "invalid email adress"),
    }
    match profile_for(TEST_EMAIL_5) {
        Ok(_expected_value) => (),
        Err(e) => panic!("valid email adress causing error {e}"),
    };
    Ok(())
}

#[test]
fn into_dict_from_dict_test() -> Result<(), anyhow::Error> {
    const INPUT: &str = "foo=bar&baz=qux&zap=zazzle";

    let expected: HashMap<String, String> = {
        let mut m = HashMap::new();
        m.insert("foo".to_string(), "bar".to_string());
        m.insert("baz".to_string(), "qux".to_string());
        m.insert("zap".to_string(), "zazzle".to_string());
        m
    };

    let object = dict_from_string(INPUT);
    assert_eq!(object, expected);

    let object = string_from_dict(expected);

    let expected_pairs: std::collections::HashSet<String> =
        INPUT.split('&').map(|s| s.to_string()).collect();
    let object_pairs: std::collections::HashSet<String> =
        object.split('&').map(|s| s.to_string()).collect();
    assert_eq!(object_pairs, expected_pairs);
    Ok(())
}
