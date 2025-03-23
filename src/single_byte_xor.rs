use crate::utils::bytes_xor;

#[derive(PartialEq, Debug)]
pub struct BreakResult {
    pub score: f32,
    pub byte: u8,
}

impl Eq for BreakResult {}

impl Ord for BreakResult {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score
            .partial_cmp(&other.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

impl PartialOrd for BreakResult {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<(usize, f32)> for BreakResult {
    fn from(value: (usize, f32)) -> Self {
        (value.0 as u8, value.1).into()
    }
}

impl From<(u8, f32)> for BreakResult {
    fn from(value: (u8, f32)) -> Self {
        BreakResult {
            score: value.1,
            byte: value.0,
        }
    }
}

/// Try to break single xor encryption by iterating over every byte
/// value, then computing an english error and returning the lowest
/// error match
pub fn try_break(input: &[u8]) -> Option<BreakResult> {
    (0..=u8::MAX)
        .map(|byte| bytes_xor(input, &[byte]))
        .map(|xored| crate::utils::english_score_bytes(&xored))
        .enumerate()
        .map(BreakResult::from)
        .min()
}
