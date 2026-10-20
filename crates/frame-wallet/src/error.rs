//! Errors a dapp sees, with EIP-1193 and EIP-5792 codes.

/// A provider error: `code` is what viem maps to its error classes (4100, 4200, 5700, 5710,
/// 5720, 5730, -32602, -32603, ...).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message} ({code})")]
pub struct ProviderError {
    pub code: i64,
    pub message: String,
}

impl ProviderError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(-32602, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(-32603, message)
    }

    pub fn unsupported_method(message: impl Into<String>) -> Self {
        Self::new(4200, message)
    }
}
