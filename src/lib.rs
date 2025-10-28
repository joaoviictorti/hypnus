#![no_std]
#![doc = include_str!("../README.md")]
#![allow(
    clippy::missing_transmute_annotations, 
    clippy::useless_transmute,
    clippy::collapsible_if,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals
)]

extern crate alloc;

mod hypnus;
mod data;
mod allocator;
mod utils;

pub use hypnus::*;
pub use allocator::*;
