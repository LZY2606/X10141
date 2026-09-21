//! 统一错误类型：所有对外失败都通过 [`Error`] 返回，接口层将其渲染为统一错误 JSON。

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    NotFound,
    InvalidRequest,
    RuleConflict,
    Unauthorized,
    Integrity,
    State,
    Crypto,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::NotFound => "not_found",
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::RuleConflict => "rule_conflict",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::Integrity => "integrity_violation",
            ErrorCode::State => "state_error",
            ErrorCode::Crypto => "crypto_error",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            ErrorCode::NotFound => 404,
            ErrorCode::InvalidRequest => 400,
            ErrorCode::RuleConflict => 409,
            ErrorCode::Unauthorized => 403,
            ErrorCode::Integrity => 500,
            ErrorCode::State => 500,
            ErrorCode::Crypto => 500,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Error {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Error::new(ErrorCode::InvalidRequest, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Error::new(ErrorCode::NotFound, message)
    }

    pub fn integrity(message: impl Into<String>) -> Self {
        Error::new(ErrorCode::Integrity, message)
    }

    pub fn state(message: impl Into<String>) -> Self {
        Error::new(ErrorCode::State, message)
    }

    pub fn crypto(message: impl Into<String>) -> Self {
        Error::new(ErrorCode::Crypto, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Error::new(ErrorCode::RuleConflict, message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
