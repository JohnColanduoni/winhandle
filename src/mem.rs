use std::{mem};
use std::ops::{Deref, DerefMut};

use kernel32::*;

pub struct LocalPtr<T>(*mut T);

impl<T> Drop for LocalPtr<T> {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0 as _); } 
    }
}

impl<T> LocalPtr<T> {
    pub unsafe fn new(value: *mut T) -> Self {
        LocalPtr(value)
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.0
    }

    pub fn into_raw(self) -> *mut T {
        let ptr = self.0;
        mem::forget(self);
        ptr
    }
}

impl<T> Deref for LocalPtr<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.0 }
    }
}

impl<T> DerefMut for LocalPtr<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.0 }
    }
}


