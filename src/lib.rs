#![no_std]
#![doc = include_str!("../README.md")]
#![allow(clippy::missing_transmute_annotations, clippy::useless_transmute)]
#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

mod config;
mod data;
mod functions;
mod gadget;
mod stack;

/// Responsible for memory obfuscation
mod hypnus;
pub use hypnus::*;

/// Custom allocator for use in Heap Obfuscation
mod allocator;
pub use allocator::*;