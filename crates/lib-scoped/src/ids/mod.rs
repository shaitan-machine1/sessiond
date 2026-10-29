//! Portable identifiers, migrated from scope-id into lib-scoped.
//!
//! Scope IDs are fully qualified `/`-separated paths, including a caller-owned
//! domain, such as `sessiond/user/1000/service`. This module knows only naming
//! syntax and conventional builders; it does not grant filesystem permissions
//! or establish policy for unprivileged scope creation.
#![forbid(unsafe_code)]

mod error;
mod target;

pub use error::ParseError;
pub use target::{MAX_TARGET_ID_LEN, TargetId, TargetIdError};

/// Maximum length, in bytes, of an encoded scope id (including `/` separators).
pub const MAX_LEN: usize = 4096;
/// Maximum length, in bytes, of a single `/`-separated segment.
pub const MAX_SEGMENT_LEN: usize = 255;
/// Maximum number of `/`-separated segments, which bounds cgroup tree depth.
pub const MAX_DEPTH: usize = 16;

/// A validated scope ID: a non-empty `/`-separated path with no empty, `.`,
/// `..` or over-long segments, using only `[A-Za-z0-9_.:-]` characters.
///
/// `ScopeId`s compare and hash by their canonical string form, which is
/// exactly the string they were parsed from (parsing does not normalize
/// anything beyond rejecting invalid input).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeId(String);

impl ScopeId {
    /// Parses and validates a scope id.
    pub fn parse(raw: impl AsRef<str>) -> Result<Self, ParseError> {
        let raw = raw.as_ref();
        if raw.is_empty() {
            return Err(ParseError::Empty);
        }
        if raw.len() > MAX_LEN {
            return Err(ParseError::TooLong);
        }
        let segments: Vec<&str> = raw.split('/').collect();
        if segments.len() > MAX_DEPTH {
            return Err(ParseError::TooDeep);
        }
        for segment in &segments {
            validate_segment(segment)?;
        }
        Ok(ScopeId(raw.to_owned()))
    }

    /// The canonical string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Iterates over the `/`-separated segments, root first.
    pub fn segments(&self) -> std::str::Split<'_, char> {
        self.0.split('/')
    }

    /// Number of `/`-separated segments.
    pub fn depth(&self) -> usize {
        self.segments().count()
    }

    /// The immediate parent, or `None` if this id has a single segment.
    pub fn parent(&self) -> Option<ScopeId> {
        self.0.rfind('/').map(|i| ScopeId(self.0[..i].to_owned()))
    }

    /// Iterates over ancestors from the immediate parent up to (and
    /// including) the top-level single-segment ancestor. Does not include
    /// `self`. Empty if this id has a single segment.
    pub fn ancestors(&self) -> Ancestors<'_> {
        Ancestors {
            current: self.0.as_str(),
        }
    }

    /// Builds the child id `self/segment`, validating `segment` on its own
    /// (it must not itself contain `/`).
    pub fn join(&self, segment: impl AsRef<str>) -> Result<ScopeId, ParseError> {
        let segment = segment.as_ref();
        validate_segment(segment)?;
        if self.depth() + 1 > MAX_DEPTH {
            return Err(ParseError::TooDeep);
        }
        Ok(ScopeId(format!("{}/{}", self.0, segment)))
    }

    /// True if `self` is `prefix` itself or a descendant of `prefix`.
    pub fn is_or_is_under(&self, prefix: &ScopeId) -> bool {
        self.0 == prefix.0
            || (self.0.len() > prefix.0.len()
                && self.0.starts_with(prefix.0.as_str())
                && self.0.as_bytes()[prefix.0.len()] == b'/')
    }

    /// If `self` is `prefix` or a descendant of it, returns the remaining
    /// suffix (empty string if `self == prefix`, otherwise without a
    /// leading `/`). `None` if `self` is not under `prefix`.
    pub fn strip_prefix(&self, prefix: &ScopeId) -> Option<&str> {
        if self.0 == prefix.0 {
            return Some("");
        }
        self.0
            .strip_prefix(prefix.0.as_str())
            .and_then(|rest| rest.strip_prefix('/'))
    }
}

impl std::fmt::Display for ScopeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ScopeId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for ScopeId {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ScopeId::parse(s)
    }
}

impl TryFrom<String> for ScopeId {
    type Error = ParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        ScopeId::parse(&s)?;
        Ok(ScopeId(s))
    }
}

impl TryFrom<&str> for ScopeId {
    type Error = ParseError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        ScopeId::parse(s)
    }
}

impl From<ScopeId> for String {
    fn from(id: ScopeId) -> String {
        id.0
    }
}

/// Iterator returned by [`ScopeId::ancestors`].
pub struct Ancestors<'a> {
    current: &'a str,
}

impl Iterator for Ancestors<'_> {
    type Item = ScopeId;

    fn next(&mut self) -> Option<ScopeId> {
        match self.current.rfind('/') {
            Some(i) => {
                let parent = &self.current[..i];
                self.current = parent;
                Some(ScopeId(parent.to_owned()))
            }
            None => None,
        }
    }
}

/// Validates a single `/`-free path segment, with the same rules
/// [`ScopeId::parse`] applies to each segment of a full id.
pub fn validate_segment(s: &str) -> Result<(), ParseError> {
    if s.is_empty() {
        return Err(ParseError::EmptySegment);
    }
    if s.len() > MAX_SEGMENT_LEN {
        return Err(ParseError::SegmentTooLong(s.to_owned()));
    }
    if s == "." || s == ".." {
        return Err(ParseError::DotSegment(s.to_owned()));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ParseError::InvalidChar(s.to_owned()));
    }
    Ok(())
}

/// Builders for the scope IDs the plan reserves under `sessiond/...` and
/// `user/...`.
pub mod well_known {
    use super::*;

    /// Conventional `user/<uid>` name. This builder grants no permissions.
    pub fn user_root(uid: u32) -> ScopeId {
        ScopeId(format!("user/{uid}"))
    }

    /// `sessiond/user/<uid>`: root-only, sessiond's own namespace for one user.
    pub fn sessiond_user_root(uid: u32) -> ScopeId {
        ScopeId(format!("sessiond/user/{uid}"))
    }

    /// `sessiond/user/<uid>/service`: the user's service manager scope.
    pub fn sessiond_user_service(uid: u32) -> ScopeId {
        ScopeId(format!("sessiond/user/{uid}/service"))
    }

    /// `sessiond/user/<uid>/session`: the prefix under which individual
    /// session scopes for this user live.
    pub fn sessiond_user_session_root(uid: u32) -> ScopeId {
        ScopeId(format!("sessiond/user/{uid}/session"))
    }

    /// `sessiond/user/<uid>/session/<sid>`: one session's scope. `sid` is
    /// validated as a single segment.
    pub fn sessiond_user_session(uid: u32, sid: &str) -> Result<ScopeId, ParseError> {
        sessiond_user_session_root(uid).join(sid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_ids() {
        for s in [
            "a",
            "sessiond/user/1000/service",
            "sessiond/user/1000/session/abc-123",
            "user/1000/My.Sandbox:1",
            "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p", // 16 segments, at the limit
        ] {
            assert!(ScopeId::parse(s).is_ok(), "{s:?} should parse");
        }
    }

    #[test]
    fn rejects_invalid_ids() {
        for s in [
            "",
            "/",
            "/a",
            "a/",
            "a//b",
            "a/./b",
            "a/../b",
            "a/b with space",
            "a/b$c",
            "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q", // 17 segments, over the limit
        ] {
            assert!(ScopeId::parse(s).is_err(), "{s:?} should not parse");
        }
    }

    #[test]
    fn rejects_overlong_segment() {
        let seg = "a".repeat(MAX_SEGMENT_LEN + 1);
        assert_eq!(
            ScopeId::parse(seg.clone()),
            Err(ParseError::SegmentTooLong(seg))
        );
    }

    #[test]
    fn parent_and_ancestors() {
        let id = ScopeId::parse("sessiond/user/1000/session/abc").unwrap();
        assert_eq!(
            id.parent(),
            Some(ScopeId::parse("sessiond/user/1000/session").unwrap())
        );
        let ancestors: Vec<ScopeId> = id.ancestors().collect();
        assert_eq!(
            ancestors,
            vec![
                ScopeId::parse("sessiond/user/1000/session").unwrap(),
                ScopeId::parse("sessiond/user/1000").unwrap(),
                ScopeId::parse("sessiond/user").unwrap(),
                ScopeId::parse("sessiond").unwrap(),
            ]
        );

        let top = ScopeId::parse("sessiond").unwrap();
        assert_eq!(top.parent(), None);
        assert_eq!(top.ancestors().count(), 0);
    }

    #[test]
    fn join_builds_child() {
        let root = ScopeId::parse("user/1000").unwrap();
        assert_eq!(
            root.join("sandbox").unwrap(),
            ScopeId::parse("user/1000/sandbox").unwrap()
        );
        assert!(root.join("a/b").is_err());
        assert!(root.join("").is_err());
    }

    #[test]
    fn is_or_is_under() {
        let prefix = ScopeId::parse("sessiond/user/1000").unwrap();
        assert!(prefix.is_or_is_under(&prefix));
        assert!(
            ScopeId::parse("sessiond/user/1000/service")
                .unwrap()
                .is_or_is_under(&prefix)
        );
        assert!(
            !ScopeId::parse("sessiond/user/10000/service")
                .unwrap()
                .is_or_is_under(&prefix)
        );
        assert!(
            !ScopeId::parse("sessiond/user")
                .unwrap()
                .is_or_is_under(&prefix)
        );
    }

    #[test]
    fn strip_prefix_works() {
        let prefix = ScopeId::parse("sessiond/user/1000/session").unwrap();
        let id = ScopeId::parse("sessiond/user/1000/session/abc").unwrap();
        assert_eq!(id.strip_prefix(&prefix), Some("abc"));
        assert_eq!(prefix.strip_prefix(&prefix), Some(""));
        let other = ScopeId::parse("sessiond/user/2000/session/abc").unwrap();
        assert_eq!(other.strip_prefix(&prefix), None);
    }

    #[test]
    fn well_known_builders() {
        assert_eq!(well_known::user_root(1000).as_str(), "user/1000");
        assert_eq!(
            well_known::sessiond_user_service(1000).as_str(),
            "sessiond/user/1000/service"
        );
        assert_eq!(
            well_known::sessiond_user_session_root(1000).as_str(),
            "sessiond/user/1000/session"
        );
        assert_eq!(
            well_known::sessiond_user_session(1000, "abc")
                .unwrap()
                .as_str(),
            "sessiond/user/1000/session/abc"
        );
        assert!(well_known::sessiond_user_session(1000, "a/b").is_err());
    }

    #[test]
    fn display_and_from_str_roundtrip() {
        let id: ScopeId = "sessiond/user/1000/service".parse().unwrap();
        assert_eq!(id.to_string(), "sessiond/user/1000/service");
        assert_eq!(id.as_str(), "sessiond/user/1000/service");
    }
}
