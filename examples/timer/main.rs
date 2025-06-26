#![no_std]
#![no_main]

extern crate alloc;

use hypnus::{timer, ObfMode, HypnusHeap};

#[unsafe(no_mangle)]
fn main() -> u8 {
    // Pointer to the memory region you want to obfuscate (e.g., shellcode)
    let data = b"\x90\x90\x90\xCC";
    let ptr = data.as_ptr() as *mut core::ffi::c_void;
    let size = data.len() as u64;

    // Sleep duration in seconds
    let delay = 5;

    // Sleep with stack spoofing and memory encryption using ThreadPool Timer
    timer!(ptr, size, delay);

    // Same, but with additional heap encryption and RWX protection
    timer!(ptr, size, delay, ObfMode::Heap | ObfMode::Rwx);

    0
}

#[global_allocator]
static ALLOCATOR: HypnusHeap = HypnusHeap;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop { }
}