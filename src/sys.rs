#![allow(bad_style)]

use std::{ptr, mem, io};
use std::ops::Deref;

use winapi::*;
use kernel32::*;
use widestring::WideCString;

pub fn HRESULT_FROM_NT(x: DWORD) -> HRESULT {
    const FACILITY_NT_BIT: DWORD = 0x10000000;

    (x | FACILITY_NT_BIT) as HRESULT
}

pub type NtQueryObjectFn = extern "system" fn(
    handle: HANDLE,
    object_information_class: OBJECT_INFORMATION_CLASS,
    object_information: PVOID,
    object_information_length: ULONG,
    return_length: PULONG,
) -> DWORD;

const GET_MODULE_HANDLE_EX_FLAG_PIN: DWORD = 0x1;

lazy_static! {
    static ref NT_DLL_HANDLE: Option<HModuleWrapper> = unsafe {
        let mut handle: HMODULE = ptr::null_mut();
        match winapi_bool_call!(GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_PIN,
            WideCString::from_str("ntdll.dll").unwrap().as_ptr(),
            &mut handle,
        )) {
            Ok(()) => Some(HModuleWrapper(handle)),
            Err(err) => {
                warn!("failed to load ntdll.dll: {}", err);
                None
            }
        }
    };
}

lazy_static! {
    pub static ref NtQueryObject: Option<NtQueryObjectFn> = unsafe {
        NT_DLL_HANDLE.and_then(|nt_dll| {
            match GetProcAddress(*nt_dll, b"NtQueryObject\0".as_ptr() as LPSTR) {
                p if p.is_null() => {
                    warn!("failed to load NtQueryObject: {}", io::Error::last_os_error());
                    None
                },
                p => mem::transmute(p),
            }
        })
    };
}

#[repr(C)]
pub enum OBJECT_INFORMATION_CLASS {
    BasicInformation = 0,
    TypeInformation = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PUBLIC_OBJECT_BASIC_INFORMATION {
    pub Attributes: ULONG,
    pub GrantedAccess: ACCESS_MASK,
    pub HandleCount: ULONG,
    pub PointerCount: ULONG,
    Reserved: [ULONG; 10],
}

#[repr(C)]
pub struct PUBLIC_OBJECT_TYPE_INFORMATION {
    pub TypeName: UNICODE_STRING,
    Reserved: [ULONG; 22],
}


// Needed for putting a module handle in a lazy_static
#[derive(Clone, Copy)]
struct HModuleWrapper(HMODULE);

unsafe impl Sync for HModuleWrapper { }

impl Deref for HModuleWrapper {
    type Target = HMODULE;

    fn deref(&self) -> &HMODULE {
        &self.0
    }
}