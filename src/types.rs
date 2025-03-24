use anyhow::anyhow;
use base64::{Engine, engine as _, engine::general_purpose::STANDARD};
use std::{fmt, str::FromStr};

// struct that holds a vector of Bytes for iterating over larger files
#[derive(Debug)]
pub struct Bytemap {
    pub bytemap: Vec<MyBytes>,
}

impl From<&str> for Bytemap {
    fn from(data: &str) -> Self {
        Bytemap {
            bytemap: data.lines().map(MyBytes::from).collect(),
        }
    }
}

impl Bytemap {
    pub fn from_hex(data: &str) -> Self {
        Bytemap {
            bytemap: data.lines().flat_map(MyBytes::from_hex).collect(),
        }
    }
}

// Struct that holds bites and easily converts them into usefull types
// or encrypted strings
#[derive(Debug)]
pub struct MyBytes {
    pub bytes: Vec<u8>,
}

impl fmt::Display for MyBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(core::format_args!(
            "{}",
            String::from_utf8_lossy(&self.bytes)
        ))
    }
}

// generic implementations
impl From<String> for MyBytes {
    fn from(data: String) -> Self {
        MyBytes::from(data.as_str())
    }
}

impl From<&str> for MyBytes {
    fn from(data: &str) -> Self {
        let bytes = data.as_bytes().to_owned();
        MyBytes { bytes }
    }
}

impl From<Vec<u8>> for MyBytes {
    fn from(bytes: Vec<u8>) -> Self {
        MyBytes { bytes }
    }
}

impl std::ops::Deref for MyBytes {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl AsRef<[u8]> for MyBytes {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl MyBytes {
    // decodes a hex encoded string into bytes
    pub fn from_hex(hex_string: &str) -> Result<MyBytes, hex::FromHexError> {
        hex::decode(hex_string).map(MyBytes::from)
    }

    // decodes a base64 string into bytes
    pub fn from_base64(base64_string: &str) -> Self {
        MyBytes::from(STANDARD.decode(base64_string).unwrap())
    }

    //returns a hex encoded string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    // returns a base64 encoded string
    pub fn to_base64(&self) -> String {
        STANDARD.encode(&self.bytes)
    }
}
