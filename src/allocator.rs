use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
    ptr::{NonNull, null_mut},
};

use dinvk::types::HANDLE;
use crate::types::HEAP_GROWABLE;

/// Global handle to the custom heap used by `HypnusHeap`.
static mut HEAP_HANDLE: Option<NonNull<c_void>> = None;

/// A thread-safe wrapper for managing a Windows Heap.
pub struct HypnusHeap;

impl HypnusHeap {
    /// Initializes a new private heap
    fn create_heap() -> HANDLE {
        let handle = unsafe { 
            RtlCreateHeap(
                HEAP_GROWABLE, 
                null_mut(), 
                0, 
                0, 
                null_mut(), 
                null_mut()
            ) 
        };
        
        let nonnull = unsafe { NonNull::new_unchecked(handle) };
        unsafe { HEAP_HANDLE = Some(nonnull) };
        handle
    }

    /// Returns the handle to the default process heap.
    pub fn get() -> HANDLE {
        unsafe { 
            HEAP_HANDLE.map(|p| p.as_ptr())
                .unwrap_or_else(Self::create_heap) 
        }
    }
}

unsafe impl GlobalAlloc for HypnusHeap {
    /// Allocates memory using the custom heap.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = Self::get();
        let size = layout.size();
        if size == 0 {
            return null_mut();
        }

        unsafe { RtlAllocateHeap(heap, 0, size) as *mut u8 }
    }

    /// Deallocates memory using the custom heap.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }

        unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
        unsafe {
            RtlFreeHeap(Self::get(), 0, ptr.cast());
        }
    }
}

windows_targets::link!("ntdll" "system" fn RtlFreeHeap(heap: HANDLE, flags: u32, ptr: *mut c_void) -> i8);
windows_targets::link!("ntdll" "system" fn RtlAllocateHeap(heap: HANDLE, flags: u32, size: usize) -> *mut c_void);
windows_targets::link!("ntdll" "system" fn RtlCreateHeap(
    flags: u32, 
    heap_base: *mut c_void, 
    reserve_size: usize, 
    commit_size: usize, 
    lock: *mut c_void, 
    parameters: *mut c_void
) -> HANDLE);
