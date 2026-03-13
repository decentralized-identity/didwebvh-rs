//! Newtype wrapper for multibase-encoded public key strings.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A multibase-encoded public key string (e.g., `"z6Mk..."`).
///
/// Provides type safety to distinguish multibase keys from arbitrary strings
/// throughout the DID WebVH parameter and witness systems.
///
/// Serializes transparently as a plain JSON string, so existing JSON formats
/// are fully preserved.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Multibase(String);

impl Multibase {
    /// Create a new `Multibase` from any string-like value.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// View the inner string as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for Multibase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Multibase {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for Multibase {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Multibase {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_shows_inner_string() {
        let m = Multibase::new("z6Mktest");
        assert_eq!(m.to_string(), "z6Mktest");
    }

    #[test]
    fn as_str_returns_inner() {
        let m = Multibase::new("z6Mktest");
        assert_eq!(m.as_str(), "z6Mktest");
    }

    #[test]
    fn into_inner_returns_owned() {
        let m = Multibase::new("z6Mktest");
        let s: String = m.into_inner();
        assert_eq!(s, "z6Mktest");
    }

    #[test]
    fn serde_roundtrip() {
        let m = Multibase::new("z6Mktest");
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"z6Mktest\"");
        let m2: Multibase = serde_json::from_str(&json).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn from_string() {
        let m: Multibase = "z6Mktest".to_string().into();
        assert_eq!(m.as_str(), "z6Mktest");
    }

    #[test]
    fn from_str_ref() {
        let m: Multibase = "z6Mktest".into();
        assert_eq!(m.as_str(), "z6Mktest");
    }

    #[test]
    fn eq_and_hash() {
        let a = Multibase::new("z6Mk1");
        let b = Multibase::new("z6Mk1");
        let c = Multibase::new("z6Mk2");
        assert_eq!(a, b);
        assert_ne!(a, c);

        // Hash consistency
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }
}
