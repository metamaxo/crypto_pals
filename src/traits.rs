use base64::{Engine, engine as _, engine::general_purpose::STANDARD};

pub trait BytesStrLinesExt: AsRef<[Vec<u8>]> {
    fn to_str(&self) -> String {
        self.as_ref()
            .iter()
            .map(|line| String::from_utf8_lossy(line).to_string())
            .collect::<Vec<String>>()
            .join("\n")
    }

    fn from_str(data: &str) -> Self
    where
        Self: Sized;
}

pub trait BytesHexLinesExt: AsRef<[Vec<u8>]> {
    fn to_hex(&self) -> String {
        self.as_ref()
            .iter()
            .map(hex::encode)
            .collect::<Vec<String>>()
            .join("\n")
    }

    fn try_from_hex(data: &str) -> Result<Self, hex::FromHexError>
    where
        Self: Sized;
}

pub trait BytesBase64Ext: AsRef<[u8]> {
    fn to_base64(&self) -> String {
        STANDARD.encode(self.as_ref())
    }
    fn try_from_base64(base64_string: &str) -> Result<Self, base64::DecodeError>
    where
        Self: Sized;
}

pub trait BytesHexExt: AsRef<[u8]> {
    fn to_hex(&self) -> String {
        hex::encode(self.as_ref())
    }
    fn try_from_hex(hex_string: &str) -> Result<Self, hex::FromHexError>
    where
        Self: Sized;
}

pub trait BytesStrExt: AsRef<[u8]> {
    fn to_str(&self) -> String {
        String::from_utf8_lossy(self.as_ref()).to_string()
    }
    fn from_str(data: &str) -> Self
    where
        Self: Sized;
}

pub trait BytesExt: BytesBase64Ext + BytesHexExt + BytesStrExt {}

impl<T> BytesExt for T where T: BytesBase64Ext + BytesHexExt + BytesStrExt {}

impl BytesBase64Ext for Vec<u8> {
    fn try_from_base64(base64_string: &str) -> Result<Self, base64::DecodeError> {
        STANDARD.decode(base64_string.trim())
    }
}

impl BytesHexExt for Vec<u8> {
    fn try_from_hex(hex_string: &str) -> Result<Self, hex::FromHexError> {
        hex::decode(hex_string.trim())
    }
}

impl BytesStrExt for Vec<u8> {
    fn from_str(data: &str) -> Self {
        data.as_bytes().to_owned()
    }
}

impl BytesStrLinesExt for Vec<Vec<u8>> {
    fn from_str(data: &str) -> Self {
        data.lines().map(<Vec<u8>>::from_str).collect()
    }
}

impl BytesHexLinesExt for Vec<Vec<u8>> {
    fn try_from_hex(data: &str) -> Result<Self, hex::FromHexError> {
        data.lines().map(<Vec<u8>>::try_from_hex).collect()
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_bytes_base64_ext() {
        use crate::traits::BytesBase64Ext;
        let original = b"Hello, World!";
        let vec = Vec::from(&original[..]);
        let base64 = vec.to_base64();
        assert_eq!(base64, "SGVsbG8sIFdvcmxkIQ==");

        let decoded = Vec::try_from_base64(&base64).unwrap();
        assert_eq!(decoded, original);

        let with_whitespace = "  SGVsbG8sIFdvcmxkIQ==  \n";
        let decoded = Vec::try_from_base64(with_whitespace).unwrap();
        assert_eq!(decoded, original);

        assert!(Vec::<u8>::try_from_base64("invalid base64!!!").is_err());
    }

    #[test]
    fn test_bytes_hex_ext() {
        use crate::traits::BytesHexExt;

        let original = b"Hello, World!";
        let vec = Vec::from(&original[..]);
        let hex = vec.to_hex();
        assert_eq!(hex, "48656c6c6f2c20576f726c6421");

        let decoded = Vec::try_from_hex(&hex).unwrap();
        assert_eq!(decoded, original);

        let with_whitespace = "  48656c6c6f2c20576f726c6421  \n";
        let decoded = Vec::try_from_hex(with_whitespace).unwrap();
        assert_eq!(decoded, original);

        assert!(Vec::<u8>::try_from_hex("invalid hex!!!").is_err());
        assert!(Vec::<u8>::try_from_hex("123").is_err()); // Odd length
    }

    #[test]
    fn test_bytes_str_ext() {
        use crate::traits::BytesStrExt;
        let original = "Hello, World!";
        let vec = Vec::from_str(original);
        assert_eq!(vec, original.as_bytes());
        assert_eq!(vec.to_str(), original);

        let invalid_utf8 = vec![0xFF, 0xFF];
        assert_eq!(
            invalid_utf8.to_str(),
            String::from_utf8_lossy(&invalid_utf8)
        );
    }

    #[test]
    fn test_bytes_str_lines_ext() {
        use crate::traits::{BytesStrLinesExt, BytesStrExt};
        let original = "Hello\nWorld\n!";
        let vec = Vec::<Vec<u8>>::from_str(original);
        assert_eq!(vec.len(), 3);
        assert_eq!(vec[0], b"Hello");
        assert_eq!(vec[1], b"World");
        assert_eq!(vec[2], b"!");

        assert_eq!(vec.to_str(), original);

        let with_empty = "\nHello\n\nWorld\n";
        let vec = Vec::<Vec<u8>>::from_str(with_empty);
        assert_eq!(vec.len(), 4);
        assert_eq!(vec[0], b"");
        assert_eq!(vec[1], b"Hello");
        assert_eq!(vec[2], b"");
        assert_eq!(vec[3], b"World");
    }

    #[test]
    fn test_bytes_hex_lines_ext() {
        use crate::traits::{BytesHexLinesExt, BytesHexExt};
        let hex_input = "48656c6c6f\n576f726c64\n21";
        let vec = Vec::<Vec<u8>>::try_from_hex(hex_input).unwrap();
        assert_eq!(vec.len(), 3);
        assert_eq!(vec[0], b"Hello");
        assert_eq!(vec[1], b"World");
        assert_eq!(vec[2], b"!");

        assert_eq!(vec.to_hex(), hex_input);

        let invalid_hex = "48656c6c6f\ninvalid\n21";
        assert!(Vec::<Vec<u8>>::try_from_hex(invalid_hex).is_err());
    }

    #[test]
    fn test_bytes_ext_combined() {
        use crate::traits::{BytesBase64Ext, BytesHexExt, BytesStrExt};
        let original = b"Hello, World!";
        let vec = Vec::from(&original[..]);

        let base64 = vec.to_base64();
        assert_eq!(Vec::try_from_base64(&base64).unwrap(), original);

        let hex = vec.to_hex();
        assert_eq!(Vec::try_from_hex(&hex).unwrap(), original);

        assert_eq!(vec.to_str(), "Hello, World!");
    }

    #[test]
    fn test_with_custom_type() {
        use crate::traits::{BytesBase64Ext, BytesHexExt, BytesStrExt};
        #[derive(Debug, PartialEq)]
        struct MyBytes(Vec<u8>);

        impl AsRef<[u8]> for MyBytes {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl BytesBase64Ext for MyBytes {
            fn try_from_base64(base64_string: &str) -> Result<Self, base64::DecodeError> {
                Vec::try_from_base64(base64_string).map(MyBytes)
            }
        }

        impl BytesHexExt for MyBytes {
            fn try_from_hex(hex_string: &str) -> Result<Self, hex::FromHexError> {
                Vec::try_from_hex(hex_string).map(MyBytes)
            }
        }

        impl BytesStrExt for MyBytes {
            fn from_str(data: &str) -> Self {
                MyBytes(Vec::from_str(data))
            }
        }

        let my_bytes = MyBytes(b"Hello, World!".to_vec());
        assert_eq!(my_bytes.to_base64(), "SGVsbG8sIFdvcmxkIQ==");
        assert_eq!(my_bytes.to_hex(), "48656c6c6f2c20576f726c6421");
        assert_eq!(my_bytes.to_str(), "Hello, World!");

        assert_eq!(
            MyBytes::try_from_base64(&my_bytes.to_base64()).unwrap(),
            my_bytes
        );
        assert_eq!(MyBytes::try_from_hex(&my_bytes.to_hex()).unwrap(), my_bytes);
        assert_eq!(MyBytes::from_str("Hello, World!"), my_bytes);
    }
}
