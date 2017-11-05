#[macro_use] extern crate log;
#[macro_use] extern crate lazy_static;

extern crate winapi;
extern crate kernel32;
#[cfg(test)] extern crate advapi32;
#[cfg(test)] extern crate user32;
extern crate widestring;

#[macro_use] pub mod macros;
mod handle;
mod comptr;
mod mem;

mod sys;

pub use handle::*;
pub use comptr::*;
pub use mem::*;

enum Opaque {}
