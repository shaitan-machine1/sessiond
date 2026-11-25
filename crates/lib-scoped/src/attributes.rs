//! Versioned whole-map scope metadata. Caller owns writer serialization.
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

pub type Attributes = BTreeMap<String, String>;
pub const MAX_ATTRIBUTE_BYTES: usize = 16 * 1024;
pub const MAX_ATTRIBUTES: usize = 128;
pub const MAX_ATTRIBUTE_NAME_BYTES: usize = 255;
pub const MAX_ATTRIBUTE_VALUE_BYTES: usize = 4096;
const NAME: &CStr = c"user.scoped.attributes";
const MAGIC: &[u8] = b"scoped-attributes-v1\0";

fn invalid(message: &str) -> Error {
    Error::io(
        "scope attributes",
        io::Error::new(io::ErrorKind::InvalidData, message),
    )
}

/// Validate before publishing. Names carry no domain-specific semantics.
pub fn validate_attributes(map: &Attributes) -> Result<()> {
    encode(map).map(|_| ())
}

fn encode(map: &Attributes) -> Result<Vec<u8>> {
    if map.len() > MAX_ATTRIBUTES {
        return Err(invalid("too many attributes"));
    }
    let mut bytes = MAGIC.to_vec();
    for (name, value) in map {
        if name.is_empty() || name.len() > MAX_ATTRIBUTE_NAME_BYTES || name.contains('\0') {
            return Err(invalid("invalid attribute name"));
        }
        if value.len() > MAX_ATTRIBUTE_VALUE_BYTES || value.contains('\0') {
            return Err(invalid("invalid attribute value"));
        }
        let addition = 8 + name.len() + value.len();
        if bytes.len() + addition > MAX_ATTRIBUTE_BYTES {
            return Err(invalid("attribute map exceeds encoded size limit"));
        }
        bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<Attributes> {
    let mut input = bytes
        .strip_prefix(MAGIC)
        .ok_or_else(|| invalid("unsupported attribute schema"))?;
    let mut map = Attributes::new();
    while !input.is_empty() {
        if input.len() < 8 {
            return Err(invalid("truncated attribute lengths"));
        }
        let name_len = u32::from_le_bytes(input[..4].try_into().expect("length checked")) as usize;
        let value_len =
            u32::from_le_bytes(input[4..8].try_into().expect("length checked")) as usize;
        input = &input[8..];
        if name_len > input.len() || value_len > input.len() - name_len {
            return Err(invalid("truncated attribute strings"));
        }
        let name = std::str::from_utf8(&input[..name_len])
            .map_err(|_| invalid("non-UTF-8 attribute name"))?;
        let value = std::str::from_utf8(&input[name_len..name_len + value_len])
            .map_err(|_| invalid("non-UTF-8 attribute value"))?;
        if map.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(invalid("duplicate attribute name"));
        }
        if map.len() > MAX_ATTRIBUTES {
            return Err(invalid("too many attributes"));
        }
        input = &input[name_len + value_len..];
    }
    validate_attributes(&map)?;
    Ok(map)
}

pub(crate) fn read(directory: &File) -> Result<Attributes> {
    // One syscall copies one complete xattr version, even under replacement.
    let mut bytes = vec![0; MAX_ATTRIBUTE_BYTES];
    // SAFETY: valid descriptor/name and writable buffer of the stated length.
    let length = unsafe {
        libc::fgetxattr(
            directory.as_raw_fd(),
            NAME.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if length < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENODATA) {
            return Ok(Attributes::new());
        }
        return Err(Error::io("read scope attributes", error));
    }
    decode(&bytes[..length as usize])
}

pub(crate) fn replace(directory: &File, map: &Attributes) -> Result<()> {
    let bytes = encode(map)?;
    // SAFETY: valid pinned descriptor, fixed name and initialized byte buffer.
    if unsafe {
        libc::fsetxattr(
            directory.as_raw_fd(),
            NAME.as_ptr(),
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
        )
    } != 0
    {
        return Err(Error::io(
            "replace scope attributes",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_is_bounded_versioned_utf8_and_domain_neutral() {
        let map = Attributes::from([
            ("XDG_SEAT".into(), "seatα".into()),
            ("runtime_dir".into(), "/arbitrary/opaque".into()),
            ("sid".into(), "not-a-session-id".into()),
        ]);
        assert_eq!(decode(&encode(&map).unwrap()).unwrap(), map);
        assert!(decode(b"v0").is_err());
        let mut bytes = encode(&map).unwrap();
        bytes.pop();
        assert!(decode(&bytes).is_err());
        assert!(validate_attributes(&Attributes::from([("".into(), "value".into())])).is_err());
        assert!(validate_attributes(&Attributes::from([("name".into(), "\0".into())])).is_err());
        assert!(
            validate_attributes(&Attributes::from([(
                "name".into(),
                "x".repeat(MAX_ATTRIBUTE_VALUE_BYTES + 1)
            )]))
            .is_err()
        );
        let many = (0..MAX_ATTRIBUTES + 1)
            .map(|n| (n.to_string(), String::new()))
            .collect();
        assert!(validate_attributes(&many).is_err());
        let large = (0..5)
            .map(|n| (n.to_string(), "x".repeat(MAX_ATTRIBUTE_VALUE_BYTES)))
            .collect();
        assert!(validate_attributes(&large).is_err());
    }
}
