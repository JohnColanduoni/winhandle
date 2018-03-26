#[doc(hidden)]
pub use winapi::shared::minwindef::{FALSE};
pub use winapi::shared::winerror::{E_FAIL, S_OK};
pub use winapi::shared::winerror::{SUCCEEDED};
pub use winapi::um::errhandlingapi::{GetLastError};
pub use winapi::um::handleapi::{INVALID_HANDLE_VALUE};

#[macro_export]
macro_rules! winapi_bool_call {
    { log: $func:ident($($x:expr),*$(,)*) } => {
        if $func(
            $($x),*
        ) == $crate::macros::FALSE {
            let err = ::std::io::Error::last_os_error();
            error!("{} failed: {}", stringify!($func), err);
            Err(err)
        } else {
            Ok(())
        }
    };
    { assert: $func:ident($($x:expr),*$(,)*) } => {
        if $func(
            $($x),*
        ) == $crate::macros::FALSE {
            let err = ::std::io::Error::last_os_error();
            panic!("{} failed: {}", stringify!($func), err);
        }
    };
    { $func:ident($($x:expr),*$(,)*) } => {
        if $func(
            $($x),*
        ) == $crate::macros::FALSE {
            Err(::std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
}

#[macro_export]
macro_rules! winapi_handle_call {
    { $func:ident($($x:expr),* $(,)*) } => { winapi_handle_call!($func($($x),*) != $crate::macros::INVALID_HANDLE_VALUE, ::std::ptr::null_mut()) };
    { $mode:ident: $func:ident($($x:expr),* $(,)*) } => { winapi_handle_call!($mode: $func($($x),*) != $crate::macros::INVALID_HANDLE_VALUE, ::std::ptr::null_mut()) };
    { log: $func:ident($($x:expr),*$(,)*) != $($invalid:expr),+ } => {
        {
            let handle = $func(
                $($x),*
            );
            if $(handle != $invalid &&)* true {
                Ok($crate::WinHandle::from_raw_unchecked(handle))
            } else {
                let err = ::std::io::Error::last_os_error();
                error!("{} failed: {}", stringify!($func), err);
                Err(err)
            }
        }
    };
    { assert: $func:ident($($x:expr),*$(,)*) != $($invalid:expr),+ } => {
        {
            let handle = $func(
                $($x),*
            );
            if $(handle != $invalid &&)* true {
                $crate::WinHandle::from_raw_unchecked(handle)
            } else {
                let err = ::std::io::Error::last_os_error();
                panic!("{} failed: {}", stringify!($func), err);
            }
        }
    };
    { $func:ident($($x:expr),*$(,)*) != $($invalid:expr),+ } => {
        {
            let handle = $func(
                $($x),*
            );
            if $(handle != $invalid &&)* true {
                Ok($crate::WinHandle::from_raw_unchecked(handle))
            } else {
                Err(::std::io::Error::last_os_error())
            }
        }
    };
}

#[macro_export]
macro_rules! winapi_hresult_call {
    { log: $func:ident( $($x:expr),* $(,)* ) } => {
        {
            let result = $func(
                $($x),*
            );

            if $crate::macros::SUCCEEDED(result) {
                Ok(result)
            } else {
                let err = ::std::io::Error::from_raw_os_error(result);
                error!("{} failed: {}", stringify!($func), err);
                Err(err)
            }
        }
    };
    { log: $recv:expr => $func:ident( $($x:expr),* $(,)*) } => {
        {
            let result = $recv.$func(
                $($x),*
            );

            if $crate::macros::SUCCEEDED(result) {
                Ok(result)
            } else {
                let err = ::std::io::Error::from_raw_os_error(result);
                error!("{} failed: {}", stringify!($func), err);
                Err(err)
            }
        }
    };
    { assert: $func:ident( $($x:expr),* $(,)* ) } => {
        {
            let result = $func(
                $($x),*
            );

            if $crate::macros::SUCCEEDED(result) {
                result
            } else {
                let err = ::std::io::Error::from_raw_os_error(result);
                panic!("{} failed: {}", stringify!($func), err);
            }
        }
    };
    { assert: $recv:expr => $func:ident( $($x:expr),* $(,)* ) } => {
        {
            let result = $recv.$func(
                $($x),*
            );

            if $crate::macros::SUCCEEDED(result) {
                result
            } else {
                let err = ::std::io::Error::from_raw_os_error(result);
                panic!("{} failed: {}", stringify!($func), err);
            }
        }
    };
    { $func:ident( $($x:expr),* $(,)* ) } => {
        {
            let result = $func(
                $($x),*
            );

            if $crate::macros::SUCCEEDED(result) {
                Ok(result)
            } else {
                Err(::std::io::Error::from_raw_os_error(result))
            }
        }
    };
    { $recv:expr => $func:ident( $($x:expr),* $(,)*) } => {
        {
            let result = $recv.$func(
                $($x),*
            );

            if $crate::macros::SUCCEEDED(result) {
                Ok(result)
            } else {
                Err(::std::io::Error::from_raw_os_error(result))
            }
        }
    };
}

#[macro_export]
macro_rules! catch_panic_hresult {
    ($body:block) => {
        match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
            $body
        })) {
            Ok(result) => result,
            Err(err) => {
                let message = err.downcast_ref::<&'static str>().map(|x| *x).or_else(|| err.downcast_ref::<String>().map(|x| &**x)).unwrap_or("unknown panic payload type");

                error!("panic in Win32/COM callback: {}", message);
                $crate::macros::E_FAIL
            },
        }
    };
    ( $r:expr ) => { catch_panic_hresult! { { $r } } };
    ( $($s:stmt;)+ $r:expr ) => { catch_panic_hresult! { { $($s;)* $r } } };
    ( $($s:stmt;)* ) => { catch_panic_hresult! { { $($s;)* #[allow(unreachable_code)] $crate::macros::S_OK } } };
}

#[cfg(test)]
mod tests {
    #[test]
    fn winapi_handle_call_ihv() {
        use std::{ptr, io};
        use winapi::um::winnt::{GENERIC_READ, FILE_ATTRIBUTE_NORMAL};
        use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};

        let err = unsafe { winapi_handle_call!(CreateFileA(
            b"\0".as_ptr() as *const i8,
            GENERIC_READ,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )) }.unwrap_err();

        assert_eq!(io::ErrorKind::NotFound, err.kind());
    }

    #[test]
    fn winapi_handle_call_null() {
        use std::{ptr};
        use winapi::shared::minwindef::{FALSE};
        use winapi::shared::winerror::{ERROR_INVALID_HANDLE};
        use winapi::um::synchapi::{CreateMutexA, CreateEventA};

        let _event = unsafe { winapi_handle_call!(CreateEventA(
            ptr::null_mut(),
            FALSE,
            FALSE,
            b"SomeRustyEvent\0".as_ptr() as *const i8,
        )) }.unwrap();

        let err = unsafe { winapi_handle_call!(CreateMutexA(
            ptr::null_mut(),
            FALSE,
            b"SomeRustyEvent\0".as_ptr() as *const i8,
        )) }.unwrap_err();

        assert_eq!(Some(ERROR_INVALID_HANDLE as i32), err.raw_os_error());
    }

    #[test]
    fn catch_panic_hresult_empty() {
        use winapi::shared::winerror::S_OK;

        let result = catch_panic_hresult! {};

        assert_eq!(S_OK, result);
    }

     #[test]
    fn catch_panic_hresult() {
        use winapi::shared::winerror::E_FAIL;

        let result = catch_panic_hresult! {
            panic!("error!");
        };

        assert_eq!(E_FAIL, result);
    }
}
