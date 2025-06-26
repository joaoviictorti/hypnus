use alloc::string::String;
use core::{ffi::c_void, ptr::null_mut};

use obfstr::{obfbytes as b, obfstring as s};
use anyhow::{Result, bail};
use dinvk::{
    data::NT_SUCCESS,
    hash::{jenkins3, murmur3},
    *,
};

use crate::{Cfg, data::*, stack::Stack};
use crate::functions::{
    NtAllocateVirtualMemory, 
    NtLockVirtualMemory, 
    NtProtectVirtualMemory
};

/// Lazily initializes and returns a singleton [`Config`] instance.
#[inline(always)]
pub fn init_config() -> anyhow::Result<&'static Config> {
    CONFIG.try_call_once(Config::new)
}

/// Global configuration object containing resolved module base addresses,
/// function pointers, and spoofed stack metadata.
static CONFIG: spin::Once<Config> = spin::Once::new();

/// Stores resolved DLL base addresses and function pointers.
#[derive(Default, Debug, Clone, Copy)]
pub struct Config {
    /// Custom thread stack, including a reserved memory region
    /// and frame sizes for spoofed call sequences
    pub stack: Stack,

    /// Callback to be executed to process NtContinue
    pub callback: u64,

    /// Trampoline function to be executed right after `RtlCaptureContext`.
    pub trampoline: u64,

    /// Address of solved modules
    pub modules: Modules,

    /// Resolvable addresses for kernel32.dll
    pub wait_for_single: WinApi,
    pub base_thread: WinApi,
    pub enum_date: WinApi,

    /// Resolvable addresses for cyptbase.dll
    pub system_function040: WinApi,
    pub system_function041: WinApi,

    /// Resolvable addresses for `ntdll.dll
    pub nt_continue: WinApi,
    pub nt_set_event: WinApi,
    pub rtl_user_thread: WinApi,
    pub nt_protect_virtual_memory: WinApi,
    pub rtl_exit_user_thread: WinApi,
    pub nt_get_context_thread: WinApi,
    pub nt_set_context_thread: WinApi,
    pub nt_test_alert: WinApi,
    pub nt_wait_for_single: WinApi,
    pub rtl_acquire_lock: WinApi,
    pub tp_release_cleanup: WinApi,
    pub rtl_capture_context: WinApi,
    pub zw_wait_for_worker: WinApi,
}

/// Holds resolved base addresses for core Windows DLLs required during initialization.
#[derive(Debug, Clone, Copy, Default)]
pub struct Modules {
    /// Base address of `ntdll.dll`.
    pub ntdll: Dll,

    /// Base address of `kernel32.dll`.
    pub kernel32: Dll,

    /// Base address of `cryptbase.dll`.
    pub cryptbase: Dll,

    /// Base address of `kernelbase.dll`.
    pub kernelbase: Dll,
}

impl Config {
    /// Create a new [`Config`].
    pub fn new() -> anyhow::Result<Self> {
        // Resolve module base addresses (ntdll, kernel32, cryptbase, etc.)
        let modules = Self::modules();

        // Resolve hashed function addresses for all required APIs
        let mut cfg = Self::functions(modules);

        // Initialize custom stack layout used for context spoofing
        cfg.stack = Stack::new(&cfg)?;

        // Allocating a callback for the NtContinue call
        cfg.callback = Self::alloc_callback()?;

        // Allocating trampoline to thread pools
        cfg.trampoline = Self::alloc_trampoline()?;

        // Register Control Flow Guard (CFG) function targets if enabled
        if let Ok(true) = Cfg::is_enabled() {
            Cfg::enable(&cfg);
        }

        Ok(cfg)
    }

    /// Allocates a small executable memory region used as a trampoline in thread pool callbacks.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` — Address of the executable trampoline stub.
    /// * `Err(anyhow::Error)` — If memory allocation or permission change fails.
    pub fn alloc_callback() -> Result<u64> {
        // Trampoline shellcode
        let callback = b!(&[
            0x48, 0x89, 0xD1, // mov rcx,rdx
            0x48, 0x8B, 0x41, 0x78, // mov rax,QWORD PTR [rcx+0x78] (CONTEXT.RAX)
            0xFF, 0xE0, // jmp rax
        ]);

        // Allocate RW memory for trampoline
        let mut size = callback.len();
        let mut addr = null_mut();
        if !NT_SUCCESS(NtAllocateVirtualMemory(
            NtCurrentProcess(), 
            &mut addr, 
            0, 
            &mut size, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        )) {
            bail!(s!("Failed to allocate stack memory"));
        }

        // Write trampoline bytes to allocated memory
        unsafe { core::ptr::copy_nonoverlapping(callback.as_ptr(), addr as *mut u8, callback.len()) };

        // Change protection to RX for execution
        let mut old_protect = 0;
        if !NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(), 
            &mut addr, 
            &mut size, 
            PAGE_EXECUTE_READ as u32, 
            &mut old_protect
        )) {
            bail!(s!("Failed to change memory protection for RX"));
        }

        // Locks the specified region of virtual memory into physical memory,
        // preventing it from being paged to disk by the memory manager.
        NtLockVirtualMemory(NtCurrentProcess(), &mut addr, &mut size, VM_LOCK_1);
        Ok(addr as u64)
    }

    /// Allocates trampoline memory for the execution of `RtlCaptureContext`
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - The address of the executable trampoline
    /// * `Err(anyhow::Error)` - If memory allocation or protection fails
    pub fn alloc_trampoline() -> Result<u64> {
        // Trampoline shellcode
        let trampoline = b!(&[
            0x48, 0x89, 0xD1, // mov rcx,rdx
            0x48, 0x31, 0xD2, // xor rdx,rdx
            0xFF, 0x21, // jmp QWORD PTR [rcx]
        ]);

        // Allocate RW memory for trampoline
        let mut size = trampoline.len();
        let mut addr = null_mut();
        if !NT_SUCCESS(NtAllocateVirtualMemory(
            NtCurrentProcess(), 
            &mut addr, 
            0, 
            &mut size, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        )) {
            bail!(s!("Failed to allocate stack memory"));
        }

        // Write trampoline bytes to allocated memory
        unsafe { core::ptr::copy_nonoverlapping(trampoline.as_ptr(), addr as *mut u8, trampoline.len()) };

        // Change protection to RX for execution
        let mut old_protect = 0;
        if !NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(), 
            &mut addr, 
            &mut size, 
            PAGE_EXECUTE_READ as u32, 
            &mut old_protect
        )) {
            bail!(s!("Failed to change memory protection for RX"));
        }

        // Locks the specified region of virtual memory into physical memory,
        // preventing it from being paged to disk by the memory manager.
        NtLockVirtualMemory(NtCurrentProcess(), &mut addr, &mut size, VM_LOCK_1);
        Ok(addr as u64)
    }

    /// Resolves the base addresses of key Windows modules (`ntdll.dll`, `kernel32.dll`, etc).
    ///
    /// # Returns
    ///  
    /// * Returns raw pointers as `*mut c_void`, which are converted to `u64` inside [`Self::functions`].
    ///
    /// # Panics
    ///
    /// * Will panic if spoofed `LoadLibraryA` call fails.
    fn modules() -> Modules {
        // Load essential DLLs
        let ntdll = get_ntdll_address();
        let kernel32 = GetModuleHandle(2808682670u32, Some(murmur3));
        let kernelbase = GetModuleHandle(2737729883u32, Some(murmur3));
        let load_library = GetProcAddress(kernel32, 4066094997u32, Some(murmur3));
        let cryptbase = {
            let mut addr = GetModuleHandle(3312853920u32, Some(murmur3));
            if addr.is_null() {
                addr = uwd::spoof!(load_library, obfstr::obfcstr!(c"CryptBase").as_ptr())
                    .expect(obfstr::obfstr!("Error"))
            }

            addr
        };

        Modules {
            ntdll: Dll::from(ntdll),
            kernel32: Dll::from(kernel32),
            cryptbase: Dll::from(cryptbase),
            kernelbase: Dll::from(kernelbase),
        }
    }

    /// Resolves hashed API function addresses using [`GetProcAddress`] and populates the [`Config`] fields.
    ///
    /// # Arguments
    ///
    /// * `modules` - A [`Modules`] struct containing base addresses for `ntdll.dll`, `kernel32.dll`, and `cryptbase.dll`.
    ///
    /// # Returns
    ///
    /// * A [`Config`] struct with resolved function pointers (without stack info).
    fn functions(modules: Modules) -> Self {
        let ntdll = modules.ntdll.as_ptr();
        let kernel32 = modules.kernel32.as_ptr();
        let cryptbase = modules.cryptbase.as_ptr();

        Self {
            modules,
            wait_for_single: GetProcAddress(kernel32, 4186526855u32, Some(jenkins3)).into(),
            base_thread: GetProcAddress(kernel32, 4083630997u32, Some(murmur3)).into(),
            enum_date: GetProcAddress(kernel32, 695401002u32, Some(jenkins3)).into(),
            system_function040: GetProcAddress(cryptbase, 1777190324, Some(murmur3)).into(),
            system_function041: GetProcAddress(cryptbase, 587184221, Some(murmur3)).into(),
            nt_continue: GetProcAddress(ntdll, 3396789853u32, Some(jenkins3)).into(),
            rtl_capture_context: GetProcAddress(ntdll, 1384243883u32, Some(jenkins3)).into(),
            nt_set_event: GetProcAddress(ntdll, 1943906260, Some(jenkins3)).into(),
            rtl_user_thread: GetProcAddress(ntdll, 1578834099, Some(murmur3)).into(),
            nt_protect_virtual_memory: GetProcAddress(ntdll, 581945446, Some(jenkins3)).into(),
            rtl_exit_user_thread: GetProcAddress(ntdll, 1518183789, Some(jenkins3)).into(),
            nt_set_context_thread: GetProcAddress(ntdll, 3400324539u32, Some(jenkins3)).into(),
            nt_get_context_thread: GetProcAddress(ntdll, 437715432, Some(jenkins3)).into(),
            nt_test_alert: GetProcAddress(ntdll, 2960797277u32, Some(murmur3)).into(),
            nt_wait_for_single: GetProcAddress(ntdll, 2606513692u32, Some(jenkins3)).into(),
            rtl_acquire_lock: GetProcAddress(ntdll, 160950224u32, Some(jenkins3)).into(),
            tp_release_cleanup: GetProcAddress(ntdll, 2871468632u32, Some(jenkins3)).into(),
            zw_wait_for_worker: GetProcAddress(ntdll, 2326337356u32, Some(jenkins3)).into(),
            ..Default::default()
        }
    }
}

/// Wrapper for DLL base addresses (`HMODULE`) stored as `u64`.
#[derive(Default, Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Dll(u64);

impl Dll {
    /// Returns the address as a mutable pointer.
    #[inline(always)]
    pub fn as_ptr(self) -> *mut c_void {
        self.0 as *mut c_void
    }

    /// Returns the address as a `u64`.
    #[inline(always)]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<*mut c_void> for Dll {
    fn from(ptr: *mut c_void) -> Self {
        Self(ptr as u64)
    }
}

impl From<u64> for Dll {
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

impl From<Dll> for u64 {
    fn from(dll: Dll) -> Self {
        dll.0
    }
}

/// Wrapper for WinAPI function pointers stored as `u64`.
#[derive(Default, Debug, Clone, Copy)]
#[repr(transparent)]
pub struct WinApi(u64);

impl WinApi {
    /// Returns the pointer as a const `*const c_void`.
    #[inline(always)]
    pub fn as_ptr(self) -> *const c_void {
        self.0 as *const c_void
    }

    /// Returns the pointer as a mutable `*mut c_void`.
    #[inline(always)]
    pub fn as_mut_ptr(self) -> *mut c_void {
        self.0 as *mut c_void
    }

    /// Returns true if the pointer is null.
    #[inline(always)]
    pub fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Returns the address as a `u64`.
    #[inline(always)]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<*const c_void> for WinApi {
    fn from(ptr: *const c_void) -> Self {
        Self(ptr as u64)
    }
}

impl From<*mut c_void> for WinApi {
    fn from(ptr: *mut c_void) -> Self {
        Self(ptr as u64)
    }
}

impl From<u64> for WinApi {
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

impl From<WinApi> for u64 {
    fn from(api: WinApi) -> Self {
        api.0
    }
}
