#![no_std]
#![no_main]

extern crate alloc;

use hypnus::{apc, ObfMode, HypnusHeap};
use core::ffi::c_void;

#[unsafe(no_mangle)]
fn main() -> u8 {
    // Pointer to the memory region you want to obfuscate (e.g., shellcode)
    let data = b"\x90\x90\x90\xCC";
    let ptr = data.as_ptr() as *mut c_void;
    let size = data.len() as u64;

    // Sleep duration in seconds
    let delay = 5;

    loop {
        // Full obfuscation with heap encryption and RWX memory protection
        apc!(ptr, size, delay, ObfMode::Heap | ObfMode::Rwx);
    }
}

#[global_allocator]
static ALLOCATOR: HypnusHeap = HypnusHeap;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop { }
}