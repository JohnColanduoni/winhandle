#[macro_use] extern crate log;

extern crate winapi;
extern crate kernel32;

#[macro_use] pub mod macros;
mod handle;
mod comptr;
mod mem;
mod wstring;

pub use handle::*;
pub use comptr::*;
pub use mem::*;
pub use wstring::*;
