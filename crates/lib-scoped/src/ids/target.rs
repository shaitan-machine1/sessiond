//! Portable, scope-local IDs for tracked process instances.

use std::fmt;

/// Maximum encoded target ID length.
///
/// Linux stores target records in an xattr whose name includes this ID;
/// keeping it compact stays well below the filesystem's 255-byte xattr-name
/// limit after the `user.scoped.target.` prefix is added.
pub const MAX_TARGET_ID_LEN: usize = 128;

/// Why a string could not be parsed as a [`TargetId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetIdError {
    Empty,
    TooLong,
    Dot(String),
    InvalidChar(String),
}

impl fmt::Display for TargetIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetIdError::Empty => write!(f, "target id is empty"),
            TargetIdError::TooLong => {
                write!(f, "target id is longer than {MAX_TARGET_ID_LEN} bytes")
            }
            TargetIdError::Dot(id) => {
                write!(f, "target id {id:?} is reserved")
            }
            TargetIdError::InvalidChar(id) => write!(
                f,
                "target id {id:?} contains a character outside [A-Za-z0-9_.-]"
            ),
        }
    }
}

impl std::error::Error for TargetIdError {}

/// A validated, caller-chosen process target ID.
///
/// Target IDs are local to one scope and deliberately contain no `/`: the
/// pair `(ScopeId, TargetId)` identifies one tracked process binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TargetId(String);

impl TargetId {
    pub fn parse(raw: impl AsRef<str>) -> Result<Self, TargetIdError> {
        let raw = raw.as_ref();
        if raw.is_empty() {
            return Err(TargetIdError::Empty);
        }
        if raw.len() > MAX_TARGET_ID_LEN {
            return Err(TargetIdError::TooLong);
        }
        if matches!(raw, "." | "..") {
            return Err(TargetIdError::Dot(raw.to_owned()));
        }
        if !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(TargetIdError::InvalidChar(raw.to_owned()));
        }
        Ok(TargetId(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TargetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for TargetId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for TargetId {
    type Err = TargetIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TargetId::parse(s)
    }
}

impl TryFrom<String> for TargetId {
    type Error = TargetIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        TargetId::parse(&value)?;
        Ok(TargetId(value))
    }
}

impl TryFrom<&str> for TargetId {
    type Error = TargetIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        TargetId::parse(value)
    }
}

impl From<TargetId> for String {
    fn from(id: TargetId) -> Self {
        id.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_portable_single_segment_ids() {
        for raw in ["manager", "compositor", "main.1", "worker_2", "a-b"] {
            assert_eq!(TargetId::parse(raw).unwrap().as_str(), raw);
        }
    }

    #[test]
    fn rejects_empty_overlong_and_unsafe_ids() {
        assert_eq!(TargetId::parse(""), Err(TargetIdError::Empty));
        assert_eq!(
            TargetId::parse("a".repeat(MAX_TARGET_ID_LEN + 1)),
            Err(TargetIdError::TooLong)
        );
        for raw in ["a/b", "two words", "a:b", "💥"] {
            assert!(matches!(
                TargetId::parse(raw),
                Err(TargetIdError::InvalidChar(_))
            ));
        }
        for raw in [".", ".."] {
            assert_eq!(
                TargetId::parse(raw),
                Err(TargetIdError::Dot(raw.to_owned()))
            );
        }
    }
}
