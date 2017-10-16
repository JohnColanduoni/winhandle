use std::{io, mem, ptr};
use std::ops::{Deref, DerefMut};
use std::os::windows::prelude::*;

use winapi::*;
use kernel32::*;

#[derive(Debug)]
pub struct WinHandle(HANDLE);

unsafe impl Send for WinHandle {
}
unsafe impl Sync for WinHandle {
}

impl Drop for WinHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0); }
        }
    }
}

pub struct WinHandleTarget(HANDLE);

impl Drop for WinHandleTarget {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0); }
        }
    }
}

impl WinHandle {
    #[inline]
    pub unsafe fn from_raw_unchecked(handle: HANDLE) -> WinHandle {
        WinHandle(handle)
    }

    /// Wraps an existing raw Windows handle while checking for validity.
    /// 
    /// Note that this function will accept INVALID_HANDLE_VALUE as this is
    /// returned by `GetCurrentProcess()`.
    pub fn from_raw(handle: HANDLE) -> Option<WinHandle> {
        unsafe {
            let mut _flags = 0;
            if GetHandleInformation(handle, &mut _flags) == TRUE {
                Some(WinHandle(handle))
            } else {
                None
            }
        }
    }

    pub fn clone(&self) -> io::Result<WinHandle> {
        Self::cloned(self)
    }

    pub fn clone_ex(&self, inheritable: bool, access: ClonedHandleAccess) -> io::Result<WinHandle> {
        Self::cloned_ex(self, inheritable, access)
    }

    pub fn cloned<T>(t: &T) -> io::Result<WinHandle> where T: AsRawHandle
    {
        Self::cloned_ex(t, false, ClonedHandleAccess::Same)
    }

    pub fn cloned_raw<T>(handle: HANDLE) -> io::Result<WinHandle>
    {
        unsafe { Self::cloned_raw_ex(handle, false, ClonedHandleAccess::Same) }
    }

    pub fn cloned_ex<T>(t: &T, inheritable: bool, access: ClonedHandleAccess) -> io::Result<WinHandle> where T: AsRawHandle
    {
        unsafe { Self::cloned_raw_ex(t.as_raw_handle(), inheritable, access) }
    }

    pub unsafe fn cloned_raw_ex(handle: HANDLE, inheritable: bool, access: ClonedHandleAccess) -> io::Result<WinHandle> {
        let (access, flags) = match access {
            ClonedHandleAccess::Same => (0, DUPLICATE_SAME_ACCESS),
            ClonedHandleAccess::Explicit(access) => (access, 0),
        };

        let mut new_handle = WinHandleTarget::new();
        winapi_bool_call!(log: DuplicateHandle(
            GetCurrentProcess(), handle,
            GetCurrentProcess(), &mut *new_handle,
            access,
            if inheritable { TRUE } else { FALSE },
            flags,
        ))?;

        Ok(new_handle.unwrap())
    }

    pub fn modify(self, inheritable: bool, access: ClonedHandleAccess) -> io::Result<WinHandle> {
        let (access, flags) = match access {
            ClonedHandleAccess::Same => (0, DUPLICATE_SAME_ACCESS),
            ClonedHandleAccess::Explicit(access) => (access, 0),
        };

        let flags = flags | DUPLICATE_CLOSE_SOURCE;

        let mut new_handle = WinHandleTarget::new();
        let old_handle = self.into_raw();
        unsafe {
            winapi_bool_call!(log: DuplicateHandle(
                GetCurrentProcess(), old_handle,
                GetCurrentProcess(), &mut *new_handle,
                access,
                if inheritable { TRUE } else { FALSE },
                flags,
            ))?;
        }

        Ok(new_handle.unwrap())
    }

    pub fn get(&self) -> HANDLE {
        self.0
    }

    pub fn into_raw(self) -> HANDLE {
        let handle = self.0;
        mem::forget(self);
        handle
    }
}

impl AsRawHandle for WinHandle {
    fn as_raw_handle(&self) -> HANDLE { self.0 }
}

impl<T> From<T> for WinHandle where T: IntoRawHandle {
    fn from(t: T) -> Self {
        WinHandle(t.into_raw_handle())
    }
}

pub enum ClonedHandleAccess {
    Same,
    Explicit(DWORD),
}

impl WinHandleTarget {
    pub fn new() -> WinHandleTarget {
        WinHandleTarget(ptr::null_mut())
    }

    #[inline]
    pub fn get(self) -> Option<WinHandle> {
        let raw = self.0;
        mem::forget(self);
        WinHandle::from_raw(raw)
    }

    #[inline]
    pub fn expect<S>(self, msg: &str) -> WinHandle {
        if let Some(handle) = self.get() {
            handle
        } else {
            panic!("{}", msg);
        }
    }

    #[inline]
    pub fn unwrap(self) -> WinHandle {
        if let Some(handle) = self.get() {
            handle
        } else {
            panic!("attempted to unwrap invalid Win32 HANDLE");
        }
    }
}

impl Deref for WinHandleTarget {
    type Target = HANDLE;

    fn deref(&self) -> &HANDLE {
        &self.0
    }
}

impl DerefMut for WinHandleTarget {
    fn deref_mut(&mut self) -> &mut HANDLE {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_current_process_handle_valid() {
        unsafe {
            let handle = WinHandle::from_raw(GetCurrentProcess()).unwrap();
            assert_eq!(GetCurrentProcess(), handle.get());
        }
    }

    #[test]
    fn null_handle_invalid() {
        assert!(!WinHandle::from_raw(0x0 as _).is_some());
    }

    #[test]
    fn random_handle_invalid() {
        assert!(!WinHandle::from_raw(0xABCD1 as _).is_some());
    }
}