use alloc::string::String;
use core::{ops::Add, ptr::null_mut};

use uwd::StackFrame;
use obfstr::obfstring as s;
use anyhow::{Context, Result, bail};
use dinvk::{
    NtCurrentProcess,
    data::{CONTEXT, NT_SUCCESS},
    parse::PE,
};

use crate::{config::Config, gadget::Gadget};
use crate::{data::*, Obfuscation};
use crate::functions::{
    NtAllocateVirtualMemory, 
    NtLockVirtualMemory, 
    NtProtectVirtualMemory
};

/// Represents a reserved stack region for custom thread execution,
/// including calculated frame sizes for known Windows APIs.
#[derive(Default, Debug, Clone, Copy)]
pub struct Stack {
    /// Address of a `gadget_rbp`, which realigns the stack (`mov rsp, rbp; ret`).
    gadget_rbp: u64,

    /// Stack frame size for `BaseThreadInitThunk`.
    base_thread_size: u32,

    /// Stack frame size for `RtlUserThreadStart`.
    rtl_user_thread_size: u32,

    /// Stack frame size for `EnumResourcesW`.
    enum_date_size: u32,

    /// Stack frame size for `RtlAcquireSRWLockExclusive`.
    rlt_acquire_srw_size: u32,

    /// Type of gadget (`call [rbx]` or `jmp [rbx]`)
    gadget: GadgetKind,
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
    /// * `Ok(GadgetKind)` - if a supported gadget is found.
    /// * `Err` - if no matching gadget is located.
    pub fn detect(base: *mut core::ffi::c_void) -> Result<Self> {
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
            GadgetKind::Call => Gadget::scan_runtime(cfg.modules.kernelbase.as_ptr(), &[0xFF, 0x13], tables)
                .context(s!("Missing call [rbx] gadget")),
            GadgetKind::Jmp => Gadget::scan_runtime(cfg.modules.kernelbase.as_ptr(), &[0xFF, 0x23], tables)
                .context(s!("Missing jmp [rbx] gadget")),
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
                0x48, 0x89, 0xEC, // mov rsp, rbp
                0xC3, // ret
            ],
            GadgetKind::Jmp => &[
                0x48, 0x89, 0xEC, // mov rsp, rbp
                0xC3, // ret
            ],
        }
    }
}

impl Stack {
    /// Create a new [`Stack`]
    ///
    /// # Arguments
    ///
    /// * `cfg` - A [`Config`] instance with loaded base addresses and function pointers.
    ///
    /// # Returns
    ///
    /// * A fully initialized [`Stack`] instance.
    #[inline(always)]
    pub fn new(cfg: &Config) -> Result<Self> {
        let mut stack = Self::alloc_memory(cfg)?;
        stack.frames(cfg)?;
        Ok(stack)
    }

    /// Allocates memory required for spoofed stack execution.
    ///
    /// # Returns
    ///
    /// * Partially constructed [`Stack`] with memory in place.
    pub fn alloc_memory(cfg: &Config) -> Result<Self> {
        // Check that the algo module contains a gadget `call [rbx]` or `jmp [rbx]`
        let kind = GadgetKind::detect(cfg.modules.kernelbase.as_ptr())?;

        // Allocate gadget code
        let bytes = kind.bytes();
        let mut gadget_code = null_mut();
        let mut code_size = 1 << 12;
        if !NT_SUCCESS(NtAllocateVirtualMemory(
            NtCurrentProcess(), 
            &mut gadget_code, 
            0, 
            &mut code_size, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        )) {
            bail!(s!("Failed to allocate memory for gadget code"));
        }

        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), gadget_code as *mut u8, bytes.len());
        }

        // Change protection to RX for execution
        let mut old_protect = 0;
        if !NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(), 
            &mut gadget_code, 
            &mut code_size, 
            PAGE_EXECUTE_READ as u32, 
            &mut old_protect
        )) {
            bail!(s!("Failed to change memory protection for RX"));
        }

        // Allocate pointer to gadget
        let mut gadget_ptr = null_mut();
        let mut ptr_size = 1 << 12;
        if !NT_SUCCESS(NtAllocateVirtualMemory(
            NtCurrentProcess(), 
            &mut gadget_ptr, 
            0, 
            &mut ptr_size, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        )) {
            bail!(s!("Failed to allocate gadget pointer page"));
        }

        unsafe {
            // Writes the gadget address (`mov rsp, rbp; ret`) to a pointer page.
            *(gadget_ptr as *mut u64) = gadget_code as u64;

            // Locks the specified region of virtual memory into physical memory,
            // preventing it from being paged to disk by the memory manager.
            NtLockVirtualMemory(NtCurrentProcess(), &mut gadget_code, &mut code_size, VM_LOCK_1);
            NtLockVirtualMemory(NtCurrentProcess(), &mut gadget_ptr, &mut ptr_size, VM_LOCK_1);
        }

        Ok(Stack {
            gadget_rbp: gadget_ptr as u64,
            gadget: kind,
            ..Default::default()
        })
    }

    /// Resolves stack frame sizes for known Windows thread routines using unwind metadata.
    ///
    /// # Arguments
    ///
    /// * `cfg` - A [`Config`] with resolved DLL base addresses and function pointers.
    ///
    /// # Returns
    ///
    /// * Error if any unwind info is missing or frame size cannot be computed.
    pub fn frames(&mut self, cfg: &Config) -> Result<()> {
        let pe_ntdll = PE::parse(cfg.modules.ntdll.as_ptr());
        let pe_kernel32 = PE::parse(cfg.modules.kernel32.as_ptr());

        let rtl_user = pe_ntdll
            .unwind()
            .function_by_offset(cfg.rtl_user_thread.as_u64() as u32 - cfg.modules.ntdll.as_u64() as u32)
            .context(s!("Missing unwind: RtlUserThreadStart"))?;

        let base_thread = pe_kernel32
            .unwind()
            .function_by_offset(cfg.base_thread.as_u64() as u32 - cfg.modules.kernel32.as_u64() as u32)
            .context(s!("Missing unwind: BaseThreadInitThunk"))?;

        let enum_date = pe_kernel32
            .unwind()
            .function_by_offset(cfg.enum_date.as_u64() as u32 - cfg.modules.kernel32.as_u64() as u32)
            .context(s!("Missing unwind: EnumDateFormatsExA"))?;

        let rtl_acquire_srw = pe_ntdll
            .unwind()
            .function_by_offset(cfg.rtl_acquire_lock.as_u64() as u32 - cfg.modules.ntdll.as_u64() as u32)
            .context(s!("Missing unwind: RtlAcquireSRWLockExclusive"))?;

        self.rtl_user_thread_size =
            StackFrame::ignoring_set_fpreg(cfg.modules.ntdll.as_ptr(), rtl_user).context(s!("Failed to get frame size: RtlUserThreadStart"))?;

        self.base_thread_size = StackFrame::ignoring_set_fpreg(cfg.modules.kernel32.as_ptr(), base_thread)
            .context(s!("Failed to get frame size: BaseThreadInitThunk"))?;

        self.enum_date_size =
            StackFrame::ignoring_set_fpreg(cfg.modules.kernel32.as_ptr(), enum_date).context(s!("Failed to get frame size: EnumDateFormatsExA"))?;

        self.rlt_acquire_srw_size = StackFrame::ignoring_set_fpreg(cfg.modules.ntdll.as_ptr(), rtl_acquire_srw)
            .context(s!("Failed to get frame size: RtlAcquireSRWLockExclusive"))?;

        Ok(())
    }

    /// Constructs a forged [`CONTEXT`] structure simulating a spoofed call chain.
    ///
    /// This function emulates a legitimate return sequence through:
    /// - `ZwWaitForWorkViaWorkerFactory`
    /// - `RtlAcquireSRWLockExclusive`  
    /// - `BaseThreadInitThunk`  
    /// - `RtlUserThreadStart`
    ///
    /// # Arguments
    ///
    /// * `cfg` - Reference to a [`Config`] containing resolved function addresses and stack sizes.
    /// * `ctx` - Original [`CONTEXT`] captured from the target thread, used as a base.
    ///
    /// # Returns
    ///
    /// * A [`CONTEXT`] with forged `RSP` and `RIP`, ready to be applied to a suspended thread.
    #[inline(always)]
    #[rustfmt::skip]
    pub fn spoof_context(&self, cfg: &Config, ctx: CONTEXT) -> CONTEXT {
        unsafe {
            // Construct a fake execution context for the current thread,
            // simulating a call stack that chains through spoofed return addresses.
            let mut ctx_spoof = CONTEXT {
                ContextFlags: CONTEXT_FULL,
                ..Default::default()
            };

            // Set the instruction pointer to the address of ZwWaitForWorkViaWorkerFactory.
            ctx_spoof.Rip = cfg.zw_wait_for_worker.as_u64();

            // Compute the spoofed RSP by subtracting all stacked frame sizes and extra alignment
            ctx_spoof.Rsp = (ctx.Rsp - 0x1000 * 5)
                - (cfg.stack.rtl_user_thread_size
                    + cfg.stack.base_thread_size
                    + cfg.stack.rlt_acquire_srw_size
                    + 32) as u64;

            // Return to RtlAcquireSRWLockExclusive + 0x17 (after call)
            *(ctx_spoof.Rsp as *mut u64) = cfg.rtl_acquire_lock.as_u64().add(0x17);

            // Return to BaseThreadInitThunk + 0x14
            *(ctx_spoof.Rsp.add((cfg.stack.rlt_acquire_srw_size + 8) as u64) as *mut u64) =
                cfg.base_thread.as_u64().add(0x14);

            // Return to RtlUserThreadStart + 0x21
            *(ctx_spoof.Rsp.add((cfg.stack.rlt_acquire_srw_size + cfg.stack.base_thread_size + 16) as u64)
                as *mut u64) = cfg.rtl_user_thread.as_u64().add(0x21);

            // End a call stack
           *(ctx_spoof.Rsp.add(
                (cfg.stack.rlt_acquire_srw_size
                    + cfg.stack.base_thread_size
                    + cfg.stack.rtl_user_thread_size
                    + 24) as u64,
            ) as *mut u64) = 0;

            ctx_spoof
        }
    }

    /// Applies a fake call stack layout to a series of thread contexts,
    /// simulating a legitimate execution.
    ///
    /// # Arguments
    ///
    /// * `ctxs` - Mutable slice of [`CONTEXT`] objects to receive the forged stack layout.
    /// * `cfg` - Reference to the [`Config`] containing resolved API addresses and gadget pointers.
    /// * `kind` - Obfuscation strategy variant [`Obfuscation`] to determine layout behavior.
    ///
    /// # Returns
    ///
    /// * Returns `Ok(())` if the stack layout was applied successfully to all contexts.
    #[rustfmt::skip]
    pub fn setup_layout(&self, ctxs: &mut [CONTEXT], cfg: &Config, kind: Obfuscation) -> Result<()> {
        let pe_kernelbase = PE::parse(cfg.modules.kernelbase.as_ptr());
        let tables = pe_kernelbase.unwind().entries().context(s!(
            "Failed to read IMAGE_RUNTIME_FUNCTION entries from .pdata section"
        ))?;

        // Locate the target COP or JOP gadget
        let (gadget_addr, gadget_size) = self.gadget.resolve(cfg)?;

        // add rsp, 0x58 ; ret
        let (add_rsp_addr, add_rsp_size) = Gadget::scan_runtime(
            cfg.modules.kernelbase.as_ptr(),
            &[0x48, 0x83, 0xC4, 0x58, 0xC3],
            tables
        ).context(s!("Add RSP gadget not found"))?;

        unsafe {
            for ctx in ctxs.iter_mut() {
                ctx.Rbp = match kind {
                    Obfuscation::Timer | Obfuscation::Wait => ctx.Rsp,
                    Obfuscation::Apc => {
                        // Inject NtTestAlert as stack return address to trigger APC delivery
                        (ctx.Rsp as *mut u64).write(cfg.nt_test_alert.into());
                        ctx.Rsp
                    }
                };

                // RBX points to our gadget pointer (mov rsp, rbp; ret)
                ctx.Rbx = cfg.stack.gadget_rbp;

                // Compute total stack size for the spoofed call chain
                ctx.Rsp = (ctx.Rsp - 0x1000 * 10)
                    - (cfg.stack.rtl_user_thread_size
                        + cfg.stack.base_thread_size
                        + cfg.stack.enum_date_size
                        + gadget_size
                        + add_rsp_size
                        + 48) as u64;

                // Stack is aligned?
                if ctx.Rsp % 16 != 0 {
                    ctx.Rsp -= 8;
                }

                // First gadget: add rsp, 0x58; ret
                *(ctx.Rsp as *mut u64) = add_rsp_addr as u64;

                // Gadget trampoline: call [rbx] || jmp [rbx]
                *(ctx.Rsp.add((add_rsp_size + 8) as u64) as *mut u64) = gadget_addr as u64;

                // Return to EnumDateFormatsExA + 0x17 (after call)
                *(ctx.Rsp.add((add_rsp_size + gadget_size + 16) as u64) as *mut u64) =
                    cfg.enum_date.as_u64().add(0x17);

                // Return to BaseThreadInitThunk + 0x14
                *(ctx.Rsp.add((cfg.stack.enum_date_size + gadget_size + add_rsp_size + 24) as u64)
                    as *mut u64) = cfg.base_thread.as_u64().add(0x14);

                // Return to RtlUserThreadStart + 0x21
                *(ctx.Rsp.add(
                    (cfg.stack.enum_date_size
                        + cfg.stack.base_thread_size
                        + gadget_size
                        + add_rsp_size
                        + 32) as u64,
                ) as *mut u64) = cfg.rtl_user_thread.as_u64().add(0x21);

                // End a call stack
                *(ctx.Rsp.add(
                   (cfg.stack.enum_date_size
                        + cfg.stack.base_thread_size
                        + cfg.stack.rtl_user_thread_size
                        + gadget_size
                        + add_rsp_size
                        + 40) as u64,
                ) as *mut u64) = 0;
            }
        }

        Ok(())
    }
}
