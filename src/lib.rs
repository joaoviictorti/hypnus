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

mod config;
mod data;
mod functions;
mod gadget;
mod stack;
mod hypnus;
mod allocator;

pub use hypnus::*;
pub use allocator::*;
