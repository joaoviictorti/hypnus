# hypnus 🦀

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![crate](https://img.shields.io/crates/v/hypnus.svg)
![docs](https://docs.rs/hypnus/badge.svg)
[![build](https://github.com/joaoviictorti/hypnus/actions/workflows/ci.yml/badge.svg)](https://github.com/joaoviictorti/hypnus/actions/workflows/ci.yml)
![Forks](https://img.shields.io/github/forks/joaoviictorti/hypnus)
![Stars](https://img.shields.io/github/stars/joaoviictorti/hypnus)
![License](https://img.shields.io/github/license/joaoviictorti/hypnus)

**Hypnus** is a Rust library for execution obfuscation, designed to protect memory regions during inactivity or sleep cycles. It leverages thread pool timers, wait objects and APC, all with dynamic call stack spoofing and optional heap obfuscation. Execution remains stealthy, and no thread duplication is required. It builds upon the dynamic spoofing foundation of the [uwd](https://github.com/joaoviictorti/uwd) library.

## Features

- ✅ Supports `#[no_std]` environments (with `alloc`).
- ✅ Call Stack Spoofing during both API execution and sleep.
- ✅ Optional Heap Obfuscation (requires `HypnusHeap` allocator).
- ✅ Automatically registers spoofed call targets in Control Flow Guard (CFG), if enabled in the process.
- ✅ The library supports three advanced sleep obfuscation techniques: it leverages ThreadPool Timers via `TpSetTimer`, ThreadPool Waits via `TpSetWait`, and APC via `NtQueueApcThread`.

## Getting started

Add `hypnus` to your project by updating your `Cargo.toml`:
```bash
cargo add hypnus
```

## Usage

To use `hypnus`, simply import the crate and call one of the obfuscation macros: `timer!`, `wait!`, or `apc!`. These macros apply memory encryption and call stack spoofing both during the sleep window and throughout the chained API calls used to encrypt and decrypt memory, ensuring full execution flow concealment.

> [!IMPORTANT]  
> If you're encrypting only specific memory regions (e.g., heap, custom buffers), using the `Rust standard library (std)` is safe. However, when encrypting the entire PE image of the current process, it's strongly recommended to use `#[no_std]`.
>
> This is not a limitation of the library, but rather a constraint imposed by Rust itself, `std` may internally access thread-local storage or perform operations that lead to access violations when the full process memory is obfuscated.

### Sleep Obfuscation via TpSetTimer

This technique is a variant of the Sleep Obfuscation method used in [Ekko](https://github.com/cracked5pider/ekko/), but it's a more evasive version that leverages the `TpSetTimer` thread pool API directly for invocation, combined with call stack spoofing.

```rs
use hypnus::timer;
use core::ffi::c_void;

fn main() {
    // Pointer to the memory region you want to obfuscate (e.g., shellcode)
    let ptr = 0x13370000 as *mut c_void;
    let size = 512;

    // Sleep duration in seconds
    let delay = 5;

    // Sleep using ThreadPool Timer
    timer!(ptr, size, delay);
}
```

### Sleep Obfuscation via TpSetWait

This technique is a variant of the Sleep Obfuscation method used in `Zilean`, but it's a more evasive version that leverages the `TpSetWait` thread pool API directly for invocation, combined with call stack spoofing.

```rs
use hypnus::wait;
use core::ffi::c_void;

fn main() {
    // Pointer to the memory region you want to obfuscate (e.g., shellcode)
    let ptr = 0x13370000 as *mut c_void;
    let size = 512;

    // Sleep duration in seconds
    let delay = 5;

    // Sleep using ThreadPool Wait
    wait!(ptr, size, delay);
}
```

### Sleep Obfuscation via APC

This technique is based on the [Foliage](https://github.com/realoriginal/foliage) method, which utilizes Asynchronous Procedure Calls (APCs) to execute spoofed callbacks on a suspended thread with call stack spoofing.

```rs
use hypnus::apc;
use core::ffi::c_void;

fn main() {
    // Pointer to the memory region you want to obfuscate (e.g., shellcode)
    let ptr = 0x13370000 as *mut c_void;
    let size = 512;

    // Sleep duration in seconds
    let delay = 5;

    // Sleep using APC
    apc!(ptr, size, delay);
}
```

### Heap Obfuscation & RWX

If you want to enable heap encryption or RWX protection, you must explicitly pass the appropriate flags via `ObfMode`. In addition, enabling heap obfuscation requires using the custom allocator provided by the library: `HypnusHeap`.

```rs
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

    // Full obfuscation with heap encryption and RWX memory protection
    apc!(ptr, size, delay, ObfMode::Heap | ObfMode::Rwx);

    0
}

#[global_allocator]
static ALLOCATOR: HypnusHeap = HypnusHeap;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop { }
}
```

## Additional Resources

For more examples, check the [examples](/examples) folder in the repository.

## References

I want to express my gratitude to these projects that inspired me to create `hypnus` and contribute with some features:

- [Ekko](https://github.com/Cracked5pider/Ekko)
- [Foliage](https://github.com/realoriginal/foliage)

## License

This project is licensed under the MIT License. See the [LICENSE](/LICENSE) file for details.
