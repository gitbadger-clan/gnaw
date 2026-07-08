//! Token counter wrapping the existing tiktoken path. The ONE place counting
//! happens in the new architecture; counts raw chunk text, so the tally
//! measures code, not formatting.

use gnaw_core::pipeline::TokenCounter;
use gnaw_core::tokenizer::{TokenizerType, count_tokens};

pub struct TiktokenCounter {
    encoding: TokenizerType,
}

impl TiktokenCounter {
    pub fn new(encoding: TokenizerType) -> Self {
        Self { encoding }
    }
}

impl TokenCounter for TiktokenCounter {
    fn count(&self, text: &str) -> usize {
        count_tokens(text, &self.encoding)
    }

    fn encoding(&self) -> TokenizerType {
        self.encoding
    }
}
