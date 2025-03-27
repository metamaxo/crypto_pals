use crate::aes_128;
use crate::aes_128::encrypt_aes128;
use crate::repeated_xor;
use crate::traits::{
    BytesBase64Ext, BytesExt, BytesHexExt, BytesHexLinesExt, BytesStrExt, BytesStrLinesExt as _,
};
use anyhow::anyhow;
use itertools::Itertools;
use std::collections::HashMap;
