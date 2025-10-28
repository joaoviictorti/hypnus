use alloc::vec::Vec;
use alloc::string::String;
use core::ffi::c_void;

use obfstr::obfstring as s;
use anyhow::{Context, Result, bail};
use dinvk::pe::PE;
use dinvk::{
    data::{CONTEXT, IMAGE_RUNTIME_FUNCTION},
};

use super::Config;

/// List of short jump opcode patterns mapped to their corresponding register.
const JMP_GADGETS: &[(&[u8], Reg)] = &[
    (&[0xFF, 0xE7], Reg::Rdi),
    (&[0x41, 0xFF, 0xE2], Reg::R10),
    (&[0x41, 0xFF, 0xE3], Reg::R11),
    (&[0x41, 0xFF, 0xE4], Reg::R12),
    (&[0x41, 0xFF, 0xE5], Reg::R13),
    (&[0x41, 0xFF, 0xE6], Reg::R14),
    (&[0x41, 0xFF, 0xE7], Reg::R15),
];

/// Enum representing x86_64 general-purpose registers suitable for indirect jumps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    Rdi,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

/// Represents a resolved jump gadget in memory.
/// Contains the absolute address and the register it jumps through.
#[derive(Debug, Clone, Copy)]
pub struct Gadget {
    /// Absolute virtual address of the gadget (e.g. `jmp rsi`)
    pub addr: u64,

    /// The register used in the jump instruction (e.g. RSI)
    pub reg: Reg,
}

impl Gadget {
    /// Injects this gadget into a given thread CONTEXT.
    ///
    /// Sets the `RIP` to the gadget address and writes the `target` value
    /// into the appropriate general-purpose register for indirect jump.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread CONTEXT to modify.
    /// * `target` - The address to jump to.
    fn apply(&self, ctx: &mut CONTEXT, target: u64) {
        ctx.Rip = self.addr;
        match self.reg {
            Reg::Rdi => ctx.Rdi = target,
            Reg::R10 => ctx.R10 = target,
            Reg::R11 => ctx.R11 = target,
            Reg::R12 => ctx.R12 = target,
            Reg::R13 => ctx.R13 = target,
            Reg::R14 => ctx.R14 = target,
            Reg::R15 => ctx.R15 = target,
        }
    }

    /// Searches for usable `jmp <reg>` gadgets in memory based on predefined opcodes.
    ///
    /// # Arguments
    ///
    /// * `cfg` – Reference to the [`Config`] containing base addresses of loaded modules.
    ///
    /// # Returns
    ///
    /// A single resolved [`Gadget`] if any were found. Panics with `unreachable_unchecked()` if none.
    pub fn resolve(cfg: &Config) -> Gadget {
        let mut gadgets = Vec::new();
        let modules = [
            cfg.modules.ntdll.as_ptr() as *const u8,
            cfg.modules.kernel32.as_ptr() as *const u8,
            cfg.modules.kernelbase.as_ptr() as *const u8,
        ];

        for &base in modules.iter() {
            if let Some(range) = Self::get_text_section(base as *mut c_void) {
                if let Some(gadget) = Self::find(base, range).first().copied() {
                    gadgets.push(gadget);
                }
            }
        }

        // Randomizes the order of possible frames found (if there is more than one),
        // helps to shuffle patterns and reduce repetition-based heuristics
        shuffle(&mut gadgets);

        if let Some(gadget) = gadgets.first().copied() {
            gadget
        } else {
            // SAFETY: `gadgets` is guaranteed to be non-empty at this point due to prior validation.
            // If this invariant is ever broken, this will invoke undefined behavior
            unsafe { core::hint::unreachable_unchecked() }
        }
    }

    /// Scans the provided memory region for `jmp <reg>` instruction patterns.
    /// Only one gadget per register is recorded to avoid redundancy.
    ///
    /// # Arguments
    ///
    /// * `base` - Base address of the module.
    /// * `region` - Memory slice to scan.
    ///
    /// # Returns
    ///
    /// A list of `Gadget` instances, one per register if available.
    fn find<B>(base: *const u8, region: &B) -> Vec<Gadget> 
    where
        B: ?Sized + AsRef<[u8]>,
    {
        let mut gadgets = Vec::new();
        let mut seen = [false; JMP_GADGETS.len()];
        for (i, (pattern, reg)) in JMP_GADGETS.iter().enumerate() {
            if seen[i] {
                continue;
            }

            // memmem::find is internally optimized with the Rabin-Karp algorithm
            // and SIMD (depending on the build), with guaranteed linear time performance (O(n))
            if let Some(pos) = memchr::memmem::find(region.as_ref(), pattern) {
                // Localized gadget: calculates absolute address based on module base
                gadgets.push(Gadget {
                    addr: base as u64 + (region.as_ref().as_ptr() as usize - base as usize + pos) as u64,
                    reg: *reg,
                });

                // Mark as found
                seen[i] = true;
            }
        }

        gadgets
    }

    /// Scans the unwind info of a PE module to locate gadgets within valid runtime functions.
    ///
    /// This scan respects function boundaries and filters out unsafe or zero-sized stack frames.
    ///
    /// # Arguments
    ///
    /// * `module` - Base address of the module
    /// * `pattern` - Instruction pattern to match (e.g., `[0xFF, 0x23]` for `jmp [rbx]`)
    /// * `runtime_table` - Slice of `IMAGE_RUNTIME_FUNCTION` entries (typically from `.pdata`)
    ///
    /// # Returns
    ///
    /// An optional tuple of (address, frame_size) for a usable gadget.
    pub fn scan_runtime<B>(
        module: *mut c_void, 
        pattern: &B, 
        runtime_table: &[IMAGE_RUNTIME_FUNCTION]
    ) -> Option<(*mut u8, u32)>
    where
        B: ?Sized + AsRef<[u8]>,
    {
        unsafe {
            let mut gadgets = Vec::new();

            for runtime in runtime_table {
                let start = module as u64 + runtime.BeginAddress as u64;
                let end = module as u64 + runtime.EndAddress as u64;
                let size = end - start;

                let bytes = core::slice::from_raw_parts(start as *const u8, size as usize);
                if let Some(pos) = memchr::memmem::find(bytes, pattern.as_ref()) {
                    let addr = (start as *mut u8).add(pos);
                    if let Some(size) = uwd::ignoring_set_fpreg(module, runtime) {
                        if size != 0 {
                            gadgets.push((addr, size))
                        }
                    }
                }
            }

            // No gadget found? return None
            if gadgets.is_empty() {
                return None;
            }

            // Randomizes the order of possible frames found (if there is more than one),
            // helps to shuffle patterns and reduce repetition-based heuristics
            shuffle(&mut gadgets);

            // Take the first occurrence
            gadgets.first().copied()
        }
    }

    /// Extracts the `.text` section from a loaded module using PE header parsing.
    ///
    /// # Arguments
    ///
    /// * `base` - Base pointer to the module in memory.
    ///
    /// # Returns
    ///
    /// An optional memory slice representing the `.text` section.
    pub fn get_text_section(base: *mut c_void) -> Option<&'static [u8]> {
        if base.is_null() {
            return None;
        }

        unsafe {
            let pe = PE::parse(base);
            let section = pe.section_by_name(obfstr::obfstr!(".text"))?;
            let ptr = base.add(section.VirtualAddress as usize);
            Some(core::slice::from_raw_parts(ptr.cast(), section.Misc.VirtualSize as usize))
        }
    }
}

/// Extension trait to allow injecting gadgets into a CONTEXT struct dynamically.
pub trait GadgetContext {
    /// Modifies the current CONTEXT instance by injecting a jump gadget.
    ///
    /// # Arguments
    ///
    /// * `cfg` - A reference to a [`Config`] struct containing base addresses.
    /// * `target` - The address that the thread should jump to.
    fn jmp(&mut self, cfg: &Config, target: u64);
}

impl GadgetContext for CONTEXT {
    fn jmp(&mut self, cfg: &Config, target: u64) {
        let gadget = Gadget::resolve(cfg);
        gadget.apply(self, target);
    }
}

/// Represents the type of gadget used to spoof control flow transitions.
#[derive(Clone, Copy, Debug, Default)]
pub enum GadgetKind {
    /// `call [rbx]` gadget
    #[default]
    Call,

    /// `jmp [rbx]` gadget
    Jmp,
}

impl GadgetKind {
    /// Scans the specified image base for a supported control-flow gadget.
    ///
    /// # Arguments
    ///
    /// * `base` - A pointer to the base address of the module to analyze.
    ///
    /// # Returns
    ///
    /// If a supported gadget is found.
    pub fn detect(base: *mut c_void) -> Result<Self> {
        let pe = PE::parse(base);
        let tables = pe.unwind().entries().context(s!("Failed to parse .pdata unwind info"))?;
        if Gadget::scan_runtime(base, &[0xFF, 0x13], tables).is_some() {
            Ok(GadgetKind::Call)
        } else if Gadget::scan_runtime(base, &[0xFF, 0x23], tables).is_some() {
            Ok(GadgetKind::Jmp)
        } else {
            bail!(s!("No suitable call/jmp [rbx] gadget found in image"));
        }
    }

    /// Resolves the actual memory address of the detected gadget in `kernelbase.dll`.
    ///
    /// # Arguments
    ///
    /// * `cfg` - A [`Config`] containing module base addresses and symbol mappings.
    ///
    /// # Returns
    ///
    /// * A tuple of `(gadget_address, gadget_size)`
    /// * `Err` if the gadget could not be found.
    pub fn resolve(&self, cfg: &Config) -> Result<(*mut u8, u32)> {
        let pe_kernelbase = PE::parse(cfg.modules.kernelbase.as_ptr());
        let tables = pe_kernelbase
            .unwind()
            .entries()
            .context(s!("Failed to read IMAGE_RUNTIME_FUNCTION entries from .pdata section"))?;

        match self {
            GadgetKind::Call => {
                Gadget::scan_runtime(cfg.modules.kernelbase.as_ptr(), &[0xFF, 0x13], tables)
                    .context(s!("Missing call [rbx] gadget"))
            }
            GadgetKind::Jmp => {
                Gadget::scan_runtime(cfg.modules.kernelbase.as_ptr(), &[0xFF, 0x23], tables)
                    .context(s!("Missing jmp [rbx] gadget"))
            }
        }
    }

    /// Returns the byte sequence representing the gadget's instruction pattern.
    ///
    /// # Returns
    ///
    /// * A static byte slice representing the chosen gadget.
    #[inline(always)]
    pub fn bytes(self) -> &'static [u8] {
        match self {
            GadgetKind::Call => &[
                0x48, 0x83, 0x2C, 0x24, 0x02, // sub qword ptr [rsp], 2
                0x48, 0x89, 0xEC,             // mov rsp, rbp
                0xC3,                         // ret
            ],
            GadgetKind::Jmp => &[
                0x48, 0x89, 0xEC, // mov rsp, rbp
                0xC3,             // ret
            ],
        }
    }
}

/// Randomly shuffles the elements of a mutable slice in-place using a pseudo-random
/// number generator seeded by the CPU's timestamp counter (`rdtsc`).
///
/// The shuffling algorithm is a variant of the Fisher-Yates shuffle.
///
/// # Arguments
/// 
/// * `list` - A mutable slice of elements to be shuffled.
pub fn shuffle<T>(list: &mut [T]) {
    let mut seed = unsafe { core::arch::x86_64::_rdtsc() };
    for i in (1..list.len()).rev() {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let j = seed as usize % (i + 1);
        list.swap(i, j);
    }
}