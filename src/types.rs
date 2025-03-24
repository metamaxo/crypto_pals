use anyhow::anyhow;
use base64::{Engine, engine as _, engine::general_purpose::STANDARD};
use std::fmt;

// struct that holds a vector of Bytes for iterating over larger files
#[derive(Debug)]
pub struct Bytemap {
    pub bytemap: Vec<Bytes>,
}

impl From<&str> for Bytemap {
    fn from(data: &str) -> Self {
        Bytemap {
            bytemap: data.lines().map(Bytes::from).collect(),
        }
    }
}
impl Bytemap {
    pub fn from_hex(data: &str) -> Self {
        Bytemap {
            bytemap: data.lines().flat_map(Bytes::from_hex).collect(),
        }
    }
}

// Struct that holds bites and easily converts them into usefull types
// or encrypted strings
#[derive(Debug)]
pub struct Bytes {
    pub bytes: Vec<u8>,
}
impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(core::format_args!(
            "{}",
            String::from_utf8_lossy(&self.bytes)
        ))
    }
}
// generic implementations
impl From<String> for Bytes {
    fn from(data: String) -> Self {
        let bytes = data.into_bytes();
        Bytes { bytes }
    }
}

impl From<&str> for Bytes {
    fn from(data: &str) -> Self {
        let bytes = data.as_bytes().to_owned();
        Bytes { bytes }
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Bytes { bytes }
    }
}
impl Bytes {
    // decodes a hex encoded string into bytes
    pub fn from_hex(hex_string: &str) -> Result<Bytes, hex::FromHexError> {
        Ok(Bytes {
            bytes: hex::decode(hex_string)?,
        })
    }
    // decodes a base64 string into bytes
    pub fn from_base64(base64_string: &str) -> Self {
        Bytes {
            bytes: STANDARD.decode(base64_string).unwrap(),
        }
    }
    //returns a hex encoded string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }
    // returns a base64 encoded string
    pub fn to_base64(&self) -> String {
        STANDARD.encode(&self.bytes)
    }
    // returns a reference of bytes
    pub fn get_ref(&self) -> &[u8] {
        &self.bytes
    }
}
