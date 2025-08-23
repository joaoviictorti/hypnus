//! # hypnus 🦀
//!
//! A Rust library for **execution obfuscation**, protecting memory regions during inactivity or sleep cycles.
//! It leverages thread pool timers, waits, and APC, with dynamic call stack spoofing and optional heap obfuscation.
//!
//! Built on top of [uwd](https://github.com/joaoviictorti/uwd).
//!
//! ## Features
//! - Sleep obfuscation with **TpSetTimer**, **TpSetWait**, or **APC**.
//! - Call stack spoofing during both API execution and sleep.
//! - Optional heap obfuscation (via [`HypnusHeap`]) and RWX control.
//! - Automatic CFG (Control Flow Guard) spoofed target registration.
//! - `#[no_std]` support (with `alloc`).
//!
//! ## Examples
//!
//! ### Sleep Obfuscation via ThreadPool Timer
//! ```no_run
//! use hypnus::timer;
//! use core::ffi::c_void;
//!
//! fn main() {
//!     let ptr = 0x13370000 as *mut c_void;
//!     let size = 512;
//!     let delay = 5;
//!     timer!(ptr, size, delay);
//! }
//! ```
//!
//! ### Sleep Obfuscation via ThreadPool Wait
//! ```no_run
//! use hypnus::wait;
//! use core::ffi::c_void;
//!
//! fn main() {
//!     let ptr = 0x13370000 as *mut c_void;
//!     let size = 512;
//!     let delay = 5;
//!     wait!(ptr, size, delay);
//! }
//! ```
//!
//! ### Sleep Obfuscation via APC (Foliage)
//! ```no_run
//! use hypnus::foliage;
//! use core::ffi::c_void;
//!
//! fn main() {
//!     let ptr = 0x13370000 as *mut c_void;
//!     let size = 512;
//!     let delay = 5;
//!     foliage!(ptr, size, delay);
//! }
//! ```
//!
//! ### Heap Obfuscation with RWX
//! ```no_run
//! #![no_std]
//! #![no_main]
//!
//! extern crate alloc;
//!
//! use hypnus::{foliage, ObfMode, HypnusHeap};
//! use core::ffi::c_void;
//!
//! #[unsafe(no_mangle)]
//! fn main() -> u8 {
//!     let data = b"\x90\x90\x90\xCC";
//!     let ptr = data.as_ptr() as *mut c_void;
//!     let size = data.len() as u64;
//!     let delay = 5;
//!
//!     foliage!(ptr, size, delay, ObfMode::Heap | ObfMode::Rwx);
//!     0
//! }
//!
//! #[global_allocator]
//! static ALLOCATOR: HypnusHeap = HypnusHeap;
//!
//! #[cfg(not(test))]
//! #[panic_handler]
//! fn panic(_info: &core::panic::PanicInfo) -> ! {
//!     loop {}
//! }
//! ```
//!
//! # More Information
//!
//! For additional examples and usage, visit the [repository].
//!
//! [repository]: https://github.com/joaoviictorti/hypnus

#![no_std]
#![allow(
    clippy::missing_transmute_annotations, 
    clippy::useless_transmute,
    clippy::collapsible_if,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals
)]

extern crate alloc;

mod config;
mod data;
mod functions;
mod gadget;
mod stack;
mod hypnus;
mod allocator;

pub use hypnus::*;
pub use allocator::*;
