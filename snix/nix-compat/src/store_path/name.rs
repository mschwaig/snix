use std::{borrow::Borrow, fmt, ops::Deref, str::FromStr};

use smol_str::SmolStr;

/// Extension for derivation names.
pub const DRV_EXT: &str = ".drv";

/// Maximum number of bytes in a store path name.
pub const MAX_NAME_LEN: usize = 211;

/// An owned validated name of a store path.
///
/// The name may only contain ASCII alphanumeric, or one of the following
/// characters: `-`, `_`, `.`, `+`, `?`, `=` and must be shorter than 211 characters long.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct StorePathNameBuf(SmolStr);

impl StorePathNameBuf {
    /// Maximum number of bytes in a store path name.
    pub const fn max_len() -> usize {
        MAX_NAME_LEN
    }

    ///Return default name of sources.
    ///
    /// # Examples
    ///
    /// ```
    /// # use nix_compat::store_path::StorePathNameBuf;
    /// assert_eq!(StorePathNameBuf::source(), "source");
    /// ```
    pub fn source() -> StorePathNameBuf {
        StorePathName::source().to_owned()
    }

    /// Checks a given `String` to match the restrictions for store path names, and
    /// returns the name as `StorePathNameBuf` if successful.
    pub fn from_string(name: String) -> Result<Self, ParseStorePathNameError> {
        validate_name(name.as_bytes())?;
        Ok(Self(SmolStr::new(name)))
    }

    /// Checks a given `SmolStr` to match the restrictions for store path names, and
    /// returns the name as `StorePathNameBuf` if successful.
    pub fn from_smol_str(name: SmolStr) -> Result<Self, ParseStorePathNameError> {
        validate_name(name.as_bytes())?;
        Ok(Self(name))
    }

    /// Checks a given `&[u8]` to match the restrictions for store path names, and
    /// returns the name as `StorePathNameBuf` if successful.
    pub fn from_slice(name: &[u8]) -> Result<Self, ParseStorePathNameError> {
        let name = validate_name(name)?;
        Ok(name.into())
    }

    /// Coerces to a [`StorePathName`] slice.
    ///
    /// # Examples
    ///
    /// ```
    /// # use nix_compat::store_path::{StorePathName, StorePathNameBuf};
    /// let name = StorePathNameBuf::try_from("snix-build").unwrap();
    /// assert_eq!(StorePathName::from_str("snix-build").unwrap(), name.as_name());
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn as_name(&self) -> &StorePathName {
        // SAFETY: A StorePathNameBuf always contains a valid store path name
        unsafe { StorePathName::from_str_unchecked(&self.0) }
    }
}

impl Default for StorePathNameBuf {
    fn default() -> Self {
        Self::source()
    }
}

impl TryFrom<String> for StorePathNameBuf {
    type Error = ParseStorePathNameError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        StorePathNameBuf::from_string(name)
    }
}

impl TryFrom<SmolStr> for StorePathNameBuf {
    type Error = ParseStorePathNameError;

    fn try_from(name: SmolStr) -> Result<Self, Self::Error> {
        StorePathNameBuf::from_smol_str(name)
    }
}

impl TryFrom<&[u8]> for StorePathNameBuf {
    type Error = ParseStorePathNameError;

    fn try_from(name: &[u8]) -> Result<Self, Self::Error> {
        StorePathNameBuf::from_slice(name)
    }
}

impl TryFrom<&str> for StorePathNameBuf {
    type Error = ParseStorePathNameError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        StorePathNameBuf::from_slice(name.as_bytes())
    }
}

impl FromStr for StorePathNameBuf {
    type Err = ParseStorePathNameError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        StorePathNameBuf::from_slice(name.as_bytes())
    }
}

impl AsRef<str> for StorePathNameBuf {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<StorePathName> for StorePathNameBuf {
    fn as_ref(&self) -> &StorePathName {
        self.as_name()
    }
}

impl Deref for StorePathNameBuf {
    type Target = StorePathName;

    fn deref(&self) -> &Self::Target {
        self.as_name()
    }
}

impl Borrow<StorePathName> for StorePathNameBuf {
    fn borrow(&self) -> &StorePathName {
        self.as_name()
    }
}

impl<'a> From<&'a StorePathName> for StorePathNameBuf {
    fn from(value: &'a StorePathName) -> Self {
        value.to_owned()
    }
}

impl PartialEq<&StorePathName> for StorePathNameBuf {
    fn eq(&self, other: &&StorePathName) -> bool {
        self.as_name() == *other
    }
}
impl PartialEq<StorePathNameBuf> for &StorePathName {
    fn eq(&self, other: &StorePathNameBuf) -> bool {
        *self == other.as_name()
    }
}
impl PartialEq<&str> for StorePathNameBuf {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}
impl PartialEq<str> for StorePathNameBuf {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}
impl PartialEq<StorePathNameBuf> for &str {
    fn eq(&self, other: &StorePathNameBuf) -> bool {
        *self == other.as_str()
    }
}
impl PartialEq<StorePathNameBuf> for str {
    fn eq(&self, other: &StorePathNameBuf) -> bool {
        self == other.as_str()
    }
}
impl PartialEq<String> for StorePathNameBuf {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}
impl PartialEq<StorePathNameBuf> for String {
    fn eq(&self, other: &StorePathNameBuf) -> bool {
        self.as_str() == other.as_str()
    }
}

impl fmt::Display for StorePathNameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validated name of a store path.
///
/// The name may only contain ASCII alphanumeric, or one of the following
/// characters: `-`, `_`, `.`, `+`, `?`, `=` and must be shorter than 211 characters long.
#[derive(Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct StorePathName(str);

impl StorePathName {
    /// Maximum number of bytes in a store path name.
    pub const fn max_len() -> usize {
        MAX_NAME_LEN
    }

    ///Return default name of sources.
    ///
    /// # Examples
    ///
    /// ```
    /// # use nix_compat::store_path::StorePathName;
    /// assert_eq!(StorePathName::source(), "source");
    /// ```
    pub const fn source() -> &'static StorePathName {
        // SAFETY: `source` is a valid StorePathName
        unsafe { StorePathName::from_str_unchecked("source") }
    }

    /// Converts a `str` to a `StorePathName` without checking that it is a valid name.
    ///
    /// # Safety
    /// This function is unsafe because it does not check that the str passed to it is a
    /// valid store path name. If this constraint is violated it may cause panics and memory safety
    /// issues , as the rest of snix assumes that `StorePathName` contains a valid store path name.
    pub const unsafe fn from_str_unchecked(name: &str) -> &StorePathName {
        // SAFETY: `str` and `StorePathName` have the same ABI because of repr(transparent)
        unsafe { &*(name as *const str as *const StorePathName) }
    }

    /// Checks a given `&str` to match the restrictions for `StorePathName`, and
    /// returns the name as `&StorePathName` if successful.
    #[expect(clippy::should_implement_trait)]
    pub fn from_str(name: &str) -> Result<&StorePathName, ParseStorePathNameError> {
        validate_name(name.as_bytes())
    }

    /// Checks a given `&[u8]` to match the restrictions for `StorePathName`, and
    /// returns the name as `&StorePathName` if successful.
    pub fn from_slice(name: &[u8]) -> Result<&StorePathName, ParseStorePathNameError> {
        validate_name(name)
    }

    /// Checks a given `OsStr` to match the restrictions for `StorePathName`, and
    /// returns the name as &StorePathName if successful
    pub fn from_os_str(name: &std::ffi::OsStr) -> Result<&StorePathName, ParseStorePathNameError> {
        validate_name(name.as_encoded_bytes())
    }

    /// Build a new `StorePathNameBuf` by adding `.drv` extension to this `StorePathName`. This
    /// fails if this name already ends in `.drv` or the resulting name would be too long.
    ///
    /// # Examples
    ///
    /// ```
    /// # use nix_compat::store_path::StorePathName;
    /// let n = StorePathName::from_str("snix-eval").unwrap();
    /// assert_eq!(n.build_drv_name().unwrap(), "snix-eval.drv");
    /// ```
    pub fn build_drv_name(&self) -> Result<StorePathNameBuf, ParseStorePathNameError> {
        if self.is_drv() {
            return Err(ParseStorePathNameError::Name);
        }
        let s = smol_str::format_smolstr!("{self}{DRV_EXT}");
        StorePathNameBuf::from_smol_str(s)
    }

    /// Returns `true` if this is the name of a derivation.
    ///
    /// Derivation names always end in `.drv` and has [`len()`] longer than 4.
    ///
    /// [`len()`]: Self::len
    ///
    /// # Examples
    ///
    /// ```
    /// # use nix_compat::store_path::StorePathName;
    /// let n = StorePathName::from_str("snix-eval").unwrap();
    /// assert!(!n.is_drv());
    ///
    /// let b = n.build_drv_name().unwrap();
    /// assert!(b.is_drv());
    /// ```
    #[must_use]
    pub fn is_drv(&self) -> bool {
        self.0.len() > DRV_EXT.len() && self.0.ends_with(DRV_EXT)
    }

    /// Remove `.drv` extension from this name or return `None` if this is not a derivation name.
    pub fn strip_drv_ext(&self) -> Option<&StorePathName> {
        self.strip_suffix(DRV_EXT)
    }

    /// Strip a suffix from this name or return `None` if the resulting name would have been empty.
    pub fn strip_suffix(&self, suffix: &str) -> Option<&StorePathName> {
        if let Some(new_name) = self.0.strip_suffix(suffix)
            && !new_name.is_empty()
        {
            // SAFETY: When removing from a name it is always shorter and still contains valid characters
            // The only exception is when all characters were stripped and that is checked above
            unsafe { Some(StorePathName::from_str_unchecked(new_name)) }
        } else {
            None
        }
    }

    /// Returns the length of this name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use nix_compat::store_path::StorePathName;
    /// assert_eq!(6, StorePathName::source().len());
    /// ```
    #[must_use]
    #[inline]
    #[expect(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Converts a name to a string. To convert the string back into a name,
    /// use the [`Self::from_str`] function.
    ///
    /// # Examples
    ///
    /// ```
    /// # use nix_compat::store_path::StorePathName;
    /// let s = StorePathName::source().as_str();
    /// assert_eq!("source", s);
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn as_str(&self) -> &str {
        &self.0
    }

    /// Converts a name to a byte slice. To convert the byte slice back into a name,
    /// use the [`Self::from_slice`] function.
    ///
    /// # Examples
    ///
    /// ```
    /// # use nix_compat::store_path::StorePathName;
    /// let bytes = StorePathName::source().as_bytes();
    /// assert_eq!(b"source", bytes);
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsRef<str> for StorePathName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for StorePathName {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<StorePathName> for StorePathName {
    fn as_ref(&self) -> &StorePathName {
        self
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a StorePathName {
    type Error = ParseStorePathNameError;

    fn try_from(name: &'a [u8]) -> Result<Self, Self::Error> {
        StorePathName::from_slice(name)
    }
}

impl<'a> TryFrom<&'a str> for &'a StorePathName {
    type Error = ParseStorePathNameError;

    fn try_from(name: &'a str) -> Result<Self, Self::Error> {
        StorePathName::from_str(name)
    }
}

impl PartialEq<&str> for StorePathName {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}
impl PartialEq<str> for StorePathName {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}
impl PartialEq<StorePathName> for &str {
    fn eq(&self, other: &StorePathName) -> bool {
        *self == other.as_str()
    }
}
impl PartialEq<StorePathName> for str {
    fn eq(&self, other: &StorePathName) -> bool {
        self == other.as_str()
    }
}
impl PartialEq<String> for StorePathName {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}
impl PartialEq<StorePathName> for String {
    fn eq(&self, other: &StorePathName) -> bool {
        self.as_str() == other.as_str()
    }
}

impl ToOwned for StorePathName {
    type Owned = StorePathNameBuf;

    fn to_owned(&self) -> Self::Owned {
        StorePathNameBuf(SmolStr::new(&self.0))
    }
}

impl fmt::Display for StorePathName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error returned when creating a [`StorePathName`].
#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum ParseStorePathNameError {
    /// Length of name was either too short (empty) or too long (longer than [`StorePathName::max_len()`]).
    #[error("Invalid length")]
    Length,
    /// Name contained invalid characters.
    #[error("Invalid name")]
    Name,
}

/// NAME_CHARS contains `true` for bytes that are valid in store path names.
static NAME_CHARS: [bool; 256] = {
    let mut tbl = [false; 256];
    let mut c = 0;

    loop {
        tbl[c as usize] = matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'-' | b'_' | b'?' | b'=' | b'.');

        if c == u8::MAX {
            break;
        }

        c += 1;
    }

    tbl
};

/// Checks a given `&[u8]` to match the restrictions for [StorePathName], and
/// returns the name as `&StorePathName` if successful.
fn validate_name(s: &[u8]) -> Result<&StorePathName, ParseStorePathNameError> {
    // Empty or excessively long names are not allowed.
    if s.is_empty() || s.len() > MAX_NAME_LEN {
        return Err(ParseStorePathNameError::Length);
    }

    let mut valid = true;
    for &c in s {
        valid = valid && NAME_CHARS[c as usize];
    }

    if !valid {
        for &c in s.iter() {
            if !NAME_CHARS[c as usize] {
                return Err(ParseStorePathNameError::Name);
            }
        }

        unreachable!();
    }

    // SAFETY: We permit a subset of ASCII, which guarantees valid UTF-8.
    let name = unsafe { std::str::from_utf8_unchecked(s) };
    // SAFETY: We have justed checked that it is a name
    let ret = unsafe { StorePathName::from_str_unchecked(name) };
    Ok(ret)
}
