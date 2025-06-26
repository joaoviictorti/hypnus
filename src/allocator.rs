use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
    ptr::{NonNull, null_mut},
};
use dinvk::{data::*, link};

/// Global handle to the custom heap used by `HypnusHeap`.
static mut HEAP_HANDLE: Option<NonNull<c_void>> = None;

/// A thread-safe wrapper for managing a Windows Heap.
pub struct HypnusHeap;

/// Allows `HypnusHeap` to be safely shared across threads.
unsafe impl Sync for HypnusHeap {}

impl HypnusHeap {
    /// Flag used to create a growable heap.
    const HEAP_GROWABLE: u32 = 0x00000002;

    /// Initializes a new private heap using `RtlCreateHeap`.
    fn create() -> HANDLE {
        let handle = unsafe { 
            RtlCreateHeap(
                Self::HEAP_GROWABLE, 
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
    pub fn heap() -> HANDLE {
        unsafe { HEAP_HANDLE.map(|p| p.as_ptr()).unwrap_or_else(Self::create) }
    }
}

unsafe impl GlobalAlloc for HypnusHeap {
    /// Allocates memory using the custom heap.
    ///
    /// # Arguments
    ///
    /// * `layout` - The memory layout to allocate.
    ///
    /// # Returns
    ///
    /// * A pointer to the allocated memory, or `ptr::null_mut()` if allocation fails.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = Self::heap();
        let size = layout.size();
        if size == 0 {
            return null_mut();
        }

        unsafe { RtlAllocateHeap(heap, 0, size) as *mut u8 }
    }

    /// Deallocates memory using the custom heap.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to the memory to deallocate.
    /// * `layout` - The memory layout.
    ///
    /// # Notes
    ///
    /// * If `ptr` is null, this function does nothing.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }

        unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
        unsafe {
            RtlFreeHeap(Self::heap(), 0, ptr.cast());
        }
    }
}

link!("ntdll" "system" fn RtlFreeHeap(heap: HANDLE, flags: u32, ptr: *mut c_void) -> i8);
link!("ntdll" "system" fn RtlAllocateHeap(heap: HANDLE, flags: u32, size: usize) -> *mut c_void);
link!("ntdll" "system" fn RtlCreateHeap(flags: u32, heap_base: *mut c_void, reserve_size: usize, commit_size: usize, lock: *mut c_void, parameters: *mut c_void) -> HANDLE);
