use ::{Opaque};
use sys::*;

use std::{fmt, io, mem, ptr};
use std::ops::{Deref, DerefMut};
use std::ffi::OsString;
use std::os::windows::prelude::*;

use winapi::*;
use kernel32::*;
use widestring::WideCStr;

pub struct WinHandle(HANDLE);

pub struct WinHandleRef(Opaque);

unsafe impl Send for WinHandle {
}
unsafe impl Sync for WinHandle {
}

unsafe impl Send for WinHandleRef {
}
unsafe impl Sync for WinHandleRef {
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
    /// returned by `GetCurrentProcess()`. Win32 functions are not altogether
    /// consistent in their error return values so this function should not be
    /// used to directly validate the return value of a Win32 function; Use the
    /// `winapi_handle_call` with appropriate error values for that.
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

    pub fn cloned<T>(t: &T) -> io::Result<WinHandle> where T: AsRawHandle {
        Self::cloned_ex(t, false, ClonedHandleAccess::Same)
    }

    pub fn cloned_raw(handle: HANDLE) -> io::Result<WinHandle> {
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

    pub fn into_raw(self) -> HANDLE {
        let handle = self.0;
        mem::forget(self);
        handle
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

}

impl Deref for WinHandle {
    type Target = WinHandleRef;

    fn deref(&self) -> &WinHandleRef {
        unsafe { mem::transmute(self.0) }
    }
}

impl WinHandleRef {
    pub fn from<T>(handle: &T) -> &Self where T: AsRawHandle {
        unsafe { Self::from_raw_unchecked(handle.as_raw_handle()) }
    }

    #[inline]
    pub unsafe fn from_raw_unchecked<'a>(handle: HANDLE) -> &'a Self {
        mem::transmute(handle)
    }

    /// Wraps an existing raw Windows handle while checking for validity.
    /// 
    /// Note that this function will accept INVALID_HANDLE_VALUE as this is
    /// returned by `GetCurrentProcess()`. Win32 functions are not altogether
    /// consistent in their error return values so this function should not be
    /// used to directly validate the return value of a Win32 function; Use the
    /// `winapi_handle_call` with appropriate error values for that.
    pub fn from_raw(handle: &HANDLE) -> Option<&Self> {
        unsafe {
            let mut _flags = 0;
            if GetHandleInformation(*handle, &mut _flags) == TRUE {
                Some(Self::from_raw_unchecked(*handle))
            } else {
                None
            }
        }
    }

    pub fn get(&self) -> HANDLE {
        unsafe { mem::transmute(self) }
    }

    pub fn clone(&self) -> io::Result<WinHandle> {
        WinHandle::cloned(self)
    }

    pub fn clone_ex(&self, inheritable: bool, access: ClonedHandleAccess) -> io::Result<WinHandle> {
        WinHandle::cloned_ex(self, inheritable, access)
    }

    pub fn kind(&self) -> io::Result<HandleKind> {
        let nt_query_object = NtQueryObject.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "NtQueryObject function not found in ntdll.dll"))?;

        unsafe {
            // Get info size
            let mut return_length: ULONG = 0;
            nt_query_object(self.get(), OBJECT_INFORMATION_CLASS::TypeInformation, ptr::null_mut(), 0, &mut return_length);
            let mut buffer = vec![0; return_length as usize];
            match HRESULT_FROM_NT(nt_query_object(self.get(), OBJECT_INFORMATION_CLASS::TypeInformation, buffer.as_mut_ptr() as PVOID, buffer.len() as ULONG, &mut return_length)) {
                s if SUCCEEDED(s) => {},
                s => return Err(io::Error::from_raw_os_error(s)),
            }
            if return_length as usize != buffer.len() || buffer.len() < mem::size_of::<PUBLIC_OBJECT_TYPE_INFORMATION>() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "NtQueryObject returned data of invalid size"));
            }

            let type_info = &*(buffer.as_ptr() as *const PUBLIC_OBJECT_TYPE_INFORMATION);
            let type_name = WideCStr::from_ptr_str(type_info.TypeName.Buffer).to_os_string();

            match type_name.to_str() {
                Some("File") => {
                    // Get the file subtype via GetFileType
                    let kind = match GetFileType(self.get()) {
                        FILE_TYPE_DISK => FileHandleKind::Disk,
                        FILE_TYPE_CHAR => FileHandleKind::Char,
                        FILE_TYPE_PIPE => FileHandleKind::Pipe,
                        FILE_TYPE_UNKNOWN => {
                            if GetLastError() != NO_ERROR {
                                return Err(io::Error::last_os_error());
                            } else {
                                FileHandleKind::Unknown
                            }
                        },
                        other => FileHandleKind::Other(other),
                    };

                    return Ok(HandleKind::File(kind));
                },
                Some("Process") => return Ok(HandleKind::Process),
                Some("Thread") => return Ok(HandleKind::Thread),
                Some("Token") => return Ok(HandleKind::AccessToken),
                Some("Job") => return Ok(HandleKind::Job),
                Some("Desktop") => return Ok(HandleKind::Desktop),
                Some("WindowStation") => return Ok(HandleKind::WindowStation),
                Some("Mutant") => return Ok(HandleKind::Mutex),
                Some("Semaphore") => return Ok(HandleKind::Semaphore),
                Some("Event") => return Ok(HandleKind::Event),
                _ => {}
            }

            Ok(HandleKind::Other(type_name))
        }
    }

    pub fn name(&self) -> io::Result<Option<OsString>> {
         let nt_query_object = NtQueryObject.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "NtQueryObject function not found in ntdll.dll"))?;

        unsafe {
            // Get info size
            let mut return_length: ULONG = 0;
            nt_query_object(self.get(), OBJECT_INFORMATION_CLASS::NameInformation, ptr::null_mut(), 0, &mut return_length);
            let mut buffer = vec![0; return_length as usize];
            match HRESULT_FROM_NT(nt_query_object(self.get(), OBJECT_INFORMATION_CLASS::NameInformation, buffer.as_mut_ptr() as PVOID, buffer.len() as ULONG, &mut return_length)) {
                s if SUCCEEDED(s) => {},
                s => return Err(io::Error::from_raw_os_error(s)),
            }
            if return_length as usize != buffer.len() || buffer.len() < mem::size_of::<PUBLIC_OBJECT_NAME_INFORMATION>() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "NtQueryObject returned data of invalid size"));
            }

            let type_info = &*(buffer.as_ptr() as *const PUBLIC_OBJECT_NAME_INFORMATION);
            if !type_info.Name.Buffer.is_null() {
                Ok(Some(WideCStr::from_ptr_str(type_info.Name.Buffer).to_os_string()))
            } else {
                Ok(None)
            }
        }
    }

    pub fn access_mask(&self) -> io::Result<ACCESS_MASK> {
        let info = self.basic_information()?;
        Ok(info.GrantedAccess)
    }

    pub fn handle_count(&self) -> io::Result<ULONG> {
        let info = self.basic_information()?;
        Ok(info.HandleCount)
    }

    fn basic_information(&self) -> io::Result<PUBLIC_OBJECT_BASIC_INFORMATION> {
        let nt_query_object = NtQueryObject.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "NtQueryObject function not found in ntdll.dll"))?;

        unsafe {
            // Get info size
            let mut return_length: ULONG = 0;
            let mut basic_info: PUBLIC_OBJECT_BASIC_INFORMATION = mem::zeroed();
            match HRESULT_FROM_NT(nt_query_object(self.get(), OBJECT_INFORMATION_CLASS::BasicInformation, &mut basic_info as *mut _ as PVOID, mem::size_of_val(&basic_info) as ULONG, &mut return_length)) {
                s if SUCCEEDED(s) => {},
                s => return Err(io::Error::from_raw_os_error(s)),
            }
            if return_length as usize != mem::size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "NtQueryObject returned data of invalid size"));
            }

            Ok(basic_info)
        }
    }
}

impl AsRawHandle for WinHandle {
    fn as_raw_handle(&self) -> HANDLE { self.get() }
}

impl AsRawHandle for WinHandleRef {
    fn as_raw_handle(&self) -> HANDLE { self.get() }
}

impl<T> From<T> for WinHandle where T: IntoRawHandle {
    fn from(t: T) -> Self {
        WinHandle(t.into_raw_handle())
    }
}

impl fmt::Debug for WinHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl fmt::Debug for WinHandleRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let (Ok(name), Ok(kind)) = (self.name(), self.kind()) {
            write!(f, "WinHandle {{ name: ")?;
            if let Some(name) = name {
                write!(f, "{:?}", name)?;
            } else {
                write!(f, "None")?;
            }
            write!(f, ", kind: {:?} }}", kind)
        } else {
            write!(f, "WinHandle({:?})", self.get())
        }
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

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum HandleKind {
    File(FileHandleKind),
    Process,
    Thread,
    AccessToken,
    Job,
    Desktop,
    WindowStation,
    Mutex,
    Semaphore,
    Event,
    Other(OsString),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum FileHandleKind {
    Disk,
    Char,
    Pipe,
    Unknown,
    Other(DWORD),
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{fs, env};

    use advapi32::*;
    use user32::*;

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


    #[test]
    fn disk_file_handle_name() {
        let path = env::current_exe().unwrap();
        let file = fs::File::open(&path).unwrap();
        let handle = WinHandle::cloned(&file).unwrap();
        let kernel_file_name = handle.name().unwrap().unwrap();
        let kernel_file_name = kernel_file_name.to_str().unwrap();
        assert!(kernel_file_name.starts_with(r#"\Device\"#));
        let mut components = path.components();
        components.next();
        assert!(kernel_file_name.ends_with(components.as_path().to_str().unwrap()));
    }

    #[test]
    fn disk_file_access_mask() {
        let file = fs::File::open(env::current_exe().unwrap()).unwrap();
        let handle = WinHandle::cloned_ex(&file, false, ClonedHandleAccess::Explicit(FILE_READ_DATA)).unwrap();
        assert_eq!(FILE_READ_DATA, handle.access_mask().unwrap());
    }

    #[test]
    fn disk_file_handle_count() {
        let file = fs::File::open(env::current_exe().unwrap()).unwrap();
        let handle = WinHandle::cloned(&file).unwrap();
        assert_eq!(2, handle.handle_count().unwrap());
    }

    #[test]
    fn disk_file_handle_kind() {
        let file = fs::File::open(env::current_exe().unwrap()).unwrap();
        let handle = WinHandle::cloned(&file).unwrap();
        assert_eq!(HandleKind::File(FileHandleKind::Disk), handle.kind().unwrap());
    }

    #[test]
    fn anon_pipe_handle_kind() {
        unsafe {
            let mut read_pipe = WinHandleTarget::new();
            let mut write_pipe = WinHandleTarget::new();
            winapi_bool_call!(assert: CreatePipe(
                &mut *read_pipe,
                &mut *write_pipe,
                ptr::null_mut(),
                0,
            ));
            let read_pipe = read_pipe.unwrap();
            assert_eq!(HandleKind::File(FileHandleKind::Pipe), read_pipe.kind().unwrap());
        }
    }

    #[test]
    fn mutex_handle_kind() {
        unsafe {
            let mutex = winapi_handle_call!(assert: CreateMutexW(
                ptr::null_mut(),
                FALSE,
                ptr::null(),
            ));
            assert_eq!(HandleKind::Mutex, mutex.kind().unwrap());
        }
    }

    #[test]
    fn semaphore_handle_kind() {
        unsafe {
            let mutex = winapi_handle_call!(assert: CreateSemaphoreW(
                ptr::null_mut(),
                0,
                1,
                ptr::null(),
            ));
            assert_eq!(HandleKind::Semaphore, mutex.kind().unwrap());
        }
    }

    #[test]
    fn event_handle_kind() {
        unsafe {
            let mutex = winapi_handle_call!(assert: CreateEventW(
                ptr::null_mut(),
                TRUE,
                TRUE,
                ptr::null(),
            ));
            assert_eq!(HandleKind::Event, mutex.kind().unwrap());
        }
    }

    #[test]
    fn current_process_handle_kind() {
        unsafe {
            let handle = WinHandle::from_raw(GetCurrentProcess()).unwrap();
            assert_eq!(HandleKind::Process, handle.kind().unwrap());
        }
    }


    #[test]
    fn current_thread_handle_kind() {
        unsafe {
            let handle = WinHandle::from_raw(GetCurrentThread()).unwrap();
            assert_eq!(HandleKind::Thread, handle.kind().unwrap());
        }
    }

    #[test]
    fn current_process_token_handle_kind() {
        unsafe {
            let mut handle = WinHandleTarget::new();
            winapi_bool_call!(assert: OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ALL_ACCESS,
                &mut *handle,
            ));
            let handle = handle.unwrap();
            assert_eq!(HandleKind::AccessToken, handle.kind().unwrap());
        }
    }

    #[test]
    fn job_handle_kind() {
        unsafe {
            let handle = winapi_handle_call!(assert: CreateJobObjectW(
                ptr::null_mut(), ptr::null_mut(),
            ));
            assert_eq!(HandleKind::Job, handle.kind().unwrap());
        }
    }

    #[test]
    fn desktop_handle_kind() {
        unsafe {
            let handle = WinHandle::from_raw(GetThreadDesktop(
                GetCurrentThreadId(),
            ) as _).unwrap();
            assert_eq!(HandleKind::Desktop, handle.kind().unwrap());
        }
    }

    #[test]
    fn winstation_handle_kind() {
        unsafe {
            let handle = WinHandle::from_raw(GetProcessWindowStation() as _).unwrap();
            assert_eq!(HandleKind::WindowStation, handle.kind().unwrap());
        }
    }

    #[link = "user32.dll"]
    extern "system" {
        fn GetProcessWindowStation() -> HWINSTA;
    }
}