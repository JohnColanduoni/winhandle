use std::{ptr, mem};
use std::ops::{Deref, DerefMut};
use std::marker::PhantomData;

use winapi::um::unknwnbase::IUnknown;

pub struct ComPtr<T>(*mut IUnknown, PhantomData<T>);
pub struct ComPtrTarget<T>(*mut IUnknown, PhantomData<T>);

impl<T> Drop for ComPtr<T> {
    fn drop(&mut self) {
        unsafe { (*self.0).Release(); }
    }
}

impl<T> Drop for ComPtrTarget<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { (*self.0).Release(); }
        }
    }
}

impl<T> ComPtr<T> {
    pub unsafe fn from_raw(raw: *mut T) -> Self {
        ComPtr(raw as *mut IUnknown, PhantomData)
    }

    pub unsafe fn from_raw_unowned(raw: *mut T) -> Self {
        (*(raw as *mut IUnknown)).AddRef();
        ComPtr(raw as *mut IUnknown, PhantomData)
    }

    pub unsafe fn force_mut(&self) -> &mut T {
        &mut *(self.0 as *mut T)
    }
}

impl<T> ComPtrTarget<T> {
    pub fn new() -> Self {
        ComPtrTarget(ptr::null_mut(), PhantomData)
    }

    pub unsafe fn as_unknown(&mut self) -> &mut ComPtrTarget<IUnknown> {
        &mut *(self as *mut ComPtrTarget<T> as *mut ComPtrTarget<IUnknown>)
    }

    pub unsafe fn get(self) -> Option<ComPtr<T>> {
        if !self.0.is_null() {
            let raw = self.0;
            mem::forget(self);
            Some(ComPtr(raw, PhantomData))
        } else {
            None
        }
    }
}

impl<T> Deref for ComPtr<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*(self.0 as *mut T) }
    }
}

impl<T> DerefMut for ComPtr<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *(self.0 as *mut T) }
    }
}

impl<T> Deref for ComPtrTarget<T> {
    type Target = *mut T;

    fn deref(&self) -> &*mut T {
        unsafe { &*(&self.0 as *const *mut IUnknown as *const *mut T) }
    }
}

impl<T> DerefMut for ComPtrTarget<T> {
    fn deref_mut(&mut self) -> &mut *mut T {
        unsafe { &mut *(&mut self.0 as *mut *mut IUnknown as *mut *mut T) }
    }
}

impl<T> Clone for ComPtr<T> {
    fn clone(&self) -> Self {
        unsafe {
            (*self.0).AddRef();
            ComPtr(self.0, PhantomData)
        }
    }
}