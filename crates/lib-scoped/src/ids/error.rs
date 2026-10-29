use std::fmt;

/// Why a string could not be parsed as a [`crate::ScopeId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input was the empty string.
    Empty,
    /// The input is longer than [`crate::MAX_LEN`] bytes.
    TooLong,
    /// The input has more than [`crate::MAX_DEPTH`] `/`-separated segments.
    TooDeep,
    /// A segment was empty. This also covers leading, trailing and doubled
    /// `/` characters, since splitting on `/` turns all of those into an
    /// empty segment.
    EmptySegment,
    /// A segment is longer than [`crate::MAX_SEGMENT_LEN`] bytes.
    SegmentTooLong(String),
    /// A segment is exactly `.` or `..`.
    DotSegment(String),
    /// A segment contains a byte outside `[A-Za-z0-9_.:-]`.
    InvalidChar(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "scope id is empty"),
            ParseError::TooLong => {
                write!(f, "scope id is longer than {} bytes", crate::MAX_LEN)
            }
            ParseError::TooDeep => {
                write!(f, "scope id has more than {} segments", crate::MAX_DEPTH)
            }
            ParseError::EmptySegment => write!(
                f,
                "scope id has an empty segment (leading, trailing or doubled '/')"
            ),
            ParseError::SegmentTooLong(s) => write!(
                f,
                "scope id segment {s:?} is longer than {} bytes",
                crate::MAX_SEGMENT_LEN
            ),
            ParseError::DotSegment(s) => {
                write!(f, "scope id segment {s:?} is '.' or '..'")
            }
            ParseError::InvalidChar(s) => write!(
                f,
                "scope id segment {s:?} contains a character outside [A-Za-z0-9_.:-]"
            ),
        }
    }
}

impl std::error::Error for ParseError {}
