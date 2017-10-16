use std::{mem, slice, fmt};
use std::ops::{Deref};
use std::fmt::Write;
use std::ffi::{OsStr, OsString};
use std::os::windows::prelude::*;

pub struct WStr([u16]);

pub struct WString(Vec<u16>);

#[derive(Clone, Debug)]
pub struct NulError;

#[derive(Clone, Debug)]
pub struct InvalidUtf16Error;

impl WString {
    pub fn new<T>(units: T) -> Result<WString, NulError> where
        T: Into<Vec<u16>>,
    {
        let mut units = units.into();
        let mut found_null = false;
        for &unit in units.iter() {
            if found_null {
                return Err(NulError);
            }
            if unit == 0 {
                found_null = true;
            }
        }
        if !found_null {
            units.push(0);
        }
        Ok(WString(units))
    }

    pub fn from<I>(string: I) -> Result<WString, NulError> where
        I: AsRef<OsStr>
    {
        let string = string.as_ref();

        let mut vec = Vec::with_capacity(string.len() + 1);
        for unit in string.encode_wide() {
            if unit == 0 {
                return Err(NulError);
            }
            vec.push(unit);
        }
        vec.push(0);

        Ok(WString(vec))
    }
}

impl Deref for WString {
    type Target = WStr;

    fn deref(&self) -> &WStr {
        unsafe {
            mem::transmute(&self.0[..])
        }
    }
}

impl WStr {
    pub fn len(&self) -> usize {
        self.0.len() - 1
    }

    pub fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }

    pub unsafe fn as_ffi_ptr(&self) -> *mut u16 {
        self.0.as_ptr() as *mut u16
    }

    pub fn units(&self) -> &[u16] {
        &self.0[0..self.0.len()-1]
    }

    pub fn to_string(&self) -> Result<String, InvalidUtf16Error> {
        let mut string = String::with_capacity(self.len());
        for c in ::std::char::decode_utf16(self.units().iter().cloned()) {
            match c {
                Ok(c) => string.push(c),
                Err(_) => return Err(InvalidUtf16Error),
            }
        }
        Ok(string)
    }

    pub fn to_string_lossy(&self) -> String {
        let mut string = String::with_capacity(self.len());
        for c in ::std::char::decode_utf16(self.units().iter().cloned()) {
            match c {
                Ok(c) => string.push(c),
                Err(_) => string.push(::std::char::REPLACEMENT_CHARACTER),
            }
        }
        string
    }

    pub unsafe fn from_null_terminated<'a>(ptr: *const u16) -> &'a Self {
        let mut end_ptr = ptr;
        while *end_ptr != 0 {
            end_ptr = end_ptr.offset(1);
        }
        end_ptr = end_ptr.offset(1);
        let len = ((end_ptr as usize) - (ptr as usize)) / mem::size_of::<u16>();
        mem::transmute(slice::from_raw_parts(ptr, len))
    }
}

impl<'a> From<&'a WStr> for OsString {
    fn from(slice: &WStr) -> OsString {
        OsStringExt::from_wide(slice.units())
    }
}

impl fmt::Debug for WStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_char('"')?;
        for c in ::std::char::decode_utf16(self.units().iter().cloned()) {
            match c {
                Ok(c) => {
                    for esc_c in c.escape_debug() {
                        f.write_char(esc_c)?;
                    }
                },
                Err(_) => f.write_char(::std::char::REPLACEMENT_CHARACTER)?,
            }
        }
        f.write_char('"')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_ptr_empty_string() {
        let units = &[0u16];
        let wstr = unsafe { WStr::from_null_terminated(units.as_ptr()) };

        assert_eq!(0, wstr.len());
        assert_eq!("", wstr.to_string().unwrap())
    }

    #[test]
    fn from_invalid_unicode() {
        let units = vec![b'a' as u16, 0xDFFFu16];
        let wstr = WString::new(units).unwrap();

        assert_eq!(2, wstr.len());
        assert_eq!(false, wstr.to_string().is_ok());
        assert_eq!("a\u{FFFD}", wstr.to_string_lossy());
    }

    #[test]
    fn from_surrogate_pair() {
        let units = vec![0xD852u16, 0xDF62];
        let wstr = WString::new(units).unwrap();

        assert_eq!(2, wstr.len());
        assert_eq!("𤭢", wstr.to_string().unwrap());
    }
}