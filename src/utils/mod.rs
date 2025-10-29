use alloc::string::String;
use core::mem::transmute;
use core::{ffi::c_void, ptr::null_mut};

use spin::Once;
use uwd::syscall;
use obfstr::{obfstr as obf, obfstring as s};
use anyhow::{Result, bail};
use dinvk::hash::{jenkins3, murmur3};
use dinvk::{
    NtCurrentProcess, GetProcAddress,
    GetModuleHandle, get_ntdll_address,
    NT_SUCCESS
};
use dinvk::data::{
    EVENT_TYPE, HANDLE, 
    LARGE_INTEGER, NTSTATUS, 
    STATUS_UNSUCCESSFUL
};

use crate::data::*;

mod spoof;
mod gadget;
mod cfg;

pub use gadget::*;
pub use spoof::*;
pub use cfg::*;

/// Global configuration object.
static CONFIG: spin::Once<Config> = spin::Once::new();

/// One-time initialization of the structure with resolved pointers.
static FUNCTIONS: Once<Functions> = Once::new();

/// Lazily initializes and returns a singleton [`Config`] instance.
#[inline(always)]
pub fn init_config() -> Result<&'static Config> {
    CONFIG.try_call_once(Config::new)
}

/// Windows DLLs required during initialization.
#[derive(Debug, Clone, Copy, Default)]
pub struct Modules {
    pub ntdll: Dll,
    pub kernel32: Dll,
    pub cryptbase: Dll,
    pub kernelbase: Dll,
}

/// Stores resolved DLL base addresses and function pointers.
#[derive(Default, Debug, Clone, Copy)]
pub struct Config {
    pub stack: StackSpoof,
    pub callback: u64,
    pub trampoline: u64,
    pub modules: Modules,
    pub wait_for_single: WinApi,
    pub base_thread: WinApi,
    pub enum_date: WinApi,
    pub system_function040: WinApi,
    pub system_function041: WinApi,
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

impl Config {
    /// Create a new `Config`.
    pub fn new() -> Result<Self> {
        // Resolve hashed function addresses for all required APIs
        let mut cfg = Self::functions(Self::modules());

        // Initialize custom stack layout used for context spoofing
        cfg.stack = StackSpoof::new(&cfg)?;

        // Allocating a callback for the NtContinue call
        cfg.callback = Self::alloc_callback()?;

        // Allocating trampoline to thread pools
        cfg.trampoline = Self::alloc_trampoline()?;

        // Register Control Flow Guard (CFG) function targets if enabled
        if let Ok(true) = is_cfg_enforced() {
            register_cfg_targets(&cfg);
        }

        Ok(cfg)
    }

    /// Allocates a small executable memory region used as a trampoline in thread pool callbacks.
    ///
    /// # Returns
    ///
    /// Address of the executable trampoline stub.
    pub fn alloc_callback() -> Result<u64> {
        // Trampoline shellcode
        let callback = &[
            0x48, 0x89, 0xD1,       // mov rcx,rdx
            0x48, 0x8B, 0x41, 0x78, // mov rax,QWORD PTR [rcx+0x78] (CONTEXT.RAX)
            0xFF, 0xE0,             // jmp rax
        ];

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
        // preventing it from being paged to disk by the memory manager
        NtLockVirtualMemory(NtCurrentProcess(), &mut addr, &mut size, VM_LOCK_1);
        Ok(addr as u64)
    }

    /// Allocates trampoline memory for the execution of `RtlCaptureContext`
    ///
    /// # Returns
    ///
    /// The address of the executable trampoline
    pub fn alloc_trampoline() -> Result<u64> {
        // Trampoline shellcode
        let trampoline = &[
            0x48, 0x89, 0xD1, // mov rcx,rdx
            0x48, 0x31, 0xD2, // xor rdx,rdx
            0xFF, 0x21,       // jmp QWORD PTR [rcx]
        ];

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
        // preventing it from being paged to disk by the memory manager
        NtLockVirtualMemory(NtCurrentProcess(), &mut addr, &mut size, VM_LOCK_1);
        Ok(addr as u64)
    }

    /// Resolves the base addresses of key Windows modules (`ntdll.dll`, `kernel32.dll`, etc).
    ///
    /// # Returns
    ///  
    /// The address of the modules
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

    /// Resolves hashed API function addresses using [`GetProcAddress`].
    ///
    /// # Arguments
    ///
    /// * `modules` - A [`Modules`] struct containing base addresses.
    ///
    /// # Returns
    ///
    /// A [`Config`] struct with resolved function pointers.
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

/// Structure containing all function pointers resolved only once.
pub struct Functions {
    pub NtSignalAndWaitForSingleObject: NtSignalAndWaitForSingleObjectFn,
    pub NtQueueApcThread: NtQueueApcThreadFn,
    pub NtAlertResumeThread: NtAlertResumeThreadFn,
    pub NtQueryInformationProcess: NtQueryInformationProcessFn,
    pub NtLockVirtualMemory: NtLockVirtualMemoryFn,
    pub NtDuplicateObject: NtDuplicateObjectFn,
    pub NtCreateEvent: NtCreateEventFn,
    pub NtWaitForSingleObject: NtWaitForSingleObjectFn,
    pub NtClose: NtCloseFn,
    pub TpAllocPool: TpAllocPoolFn,
    pub TpSetPoolStackInformation: TpSetPoolStackInformationFn,
    pub TpSetPoolMinThreads: TpSetPoolMinThreadsFn,
    pub TpSetPoolMaxThreads: TpSetPoolMaxThreadsFn,
    pub TpAllocTimer: TpAllocFn,
    pub TpSetTimer: TpSetTimerFn,
    pub TpAllocWait: TpAllocFn,
    pub TpSetWait: TpSetWaitFn,
    pub NtSetEvent: NtSetEventFn,
    pub CloseThreadpool: CloseThreadpoolFn,
    pub RtlWalkHeap: RtlWalkHeapFn,
    pub SetProcessValidCallTargets: SetProcessValidCallTargetsFn,
    pub ConvertFiberToThread: ConvertFiberToThreadFn,
    pub ConvertThreadToFiber: ConvertThreadToFiberFn,
    pub CreateFiber: CreateFiberFn,
    pub DeleteFiber: DeleteFiberFn,
    pub SwitchToFiber: SwitchToFiberFn,
}

/// Returns a reference to the resolved functions structure.
#[inline(always)]
pub fn functions() -> &'static Functions {
    FUNCTIONS.call_once(|| {
        let ntdll = get_ntdll_address();
        let kernelbase = GetModuleHandle(2737729883u32, Some(murmur3));
        let kernel32 = GetModuleHandle(2808682670u32, Some(murmur3));
        unsafe {
            Functions {
                NtSignalAndWaitForSingleObject: transmute(GetProcAddress(ntdll, 2343758301u32, Some(jenkins3))),
                NtQueueApcThread: transmute(GetProcAddress(ntdll, 2047395029u32, Some(jenkins3))),
                NtAlertResumeThread: transmute(GetProcAddress(ntdll, 3894675502u32, Some(jenkins3))),
                NtQueryInformationProcess: transmute(GetProcAddress(ntdll, 2237456582u32, Some(jenkins3))),
                NtLockVirtualMemory: transmute(GetProcAddress(ntdll, 4166947453u32, Some(jenkins3))),
                NtDuplicateObject: transmute(GetProcAddress(ntdll, 2175435662u32, Some(jenkins3))),
                NtCreateEvent: transmute(GetProcAddress(ntdll, 1593028964u32, Some(jenkins3))),
                NtWaitForSingleObject: transmute(GetProcAddress(ntdll, 2606513692u32, Some(jenkins3))),
                NtClose: transmute(GetProcAddress(ntdll, 3317382880u32, Some(jenkins3))),
                TpAllocPool: transmute(GetProcAddress(ntdll, 2447693371u32, Some(jenkins3))),
                TpSetPoolStackInformation: transmute(GetProcAddress(ntdll, 602502226u32, Some(jenkins3))),
                TpSetPoolMinThreads: transmute(GetProcAddress(ntdll, 719914357u32, Some(jenkins3))),
                TpSetPoolMaxThreads: transmute(GetProcAddress(ntdll, 2333365797u32, Some(jenkins3))),
                TpAllocTimer: transmute(GetProcAddress(ntdll, 2608438500u32, Some(jenkins3))),
                TpSetTimer: transmute(GetProcAddress(ntdll, 3984996346u32, Some(jenkins3))),
                TpAllocWait: transmute(GetProcAddress(ntdll, 1490509702u32, Some(jenkins3))),
                TpSetWait: transmute(GetProcAddress(ntdll, 47310713u32, Some(jenkins3))),
                NtSetEvent: transmute(GetProcAddress(ntdll, 1943906260u32, Some(jenkins3))),
                CloseThreadpool: transmute(GetProcAddress(kernel32, 4211127317u32, Some(jenkins3))),
                RtlWalkHeap: transmute(GetProcAddress(ntdll, 428298494u32, Some(jenkins3))),
                SetProcessValidCallTargets: transmute(GetProcAddress(kernelbase, 2887664134u32, Some(jenkins3))),
                ConvertFiberToThread: transmute(GetProcAddress(kernelbase, 3102155314u32, Some(jenkins3))),
                ConvertThreadToFiber: transmute(GetProcAddress(kernelbase, 3394836561u32, Some(jenkins3))),
                CreateFiber: transmute(GetProcAddress(kernelbase, 620670734u32, Some(jenkins3))),
                DeleteFiber: transmute(GetProcAddress(kernelbase, 1500260625u32, Some(jenkins3))),
                SwitchToFiber: transmute(GetProcAddress(kernelbase, 954746181u32, Some(jenkins3))),
            }
        }
    })
}

/// Wrapper for the `NtClose` API.
#[inline(always)]
pub fn NtClose(Handle: HANDLE) -> NTSTATUS {
    unsafe { (functions().NtClose)(Handle) }
}

/// Wrapper for the `NtSetEvent` API.
#[inline(always)]
pub fn NtSetEvent(hEvent: *mut c_void, PreviousState: *mut i32) -> NTSTATUS {
    unsafe { (functions().NtSetEvent)(hEvent, PreviousState) }
}

/// Wrapper for the `NtWaitForSingleObject` API.
#[inline(always)]
pub fn NtWaitForSingleObject(Handle: HANDLE, Alertable: u8, Timeout: *mut i32) -> NTSTATUS {
    unsafe { (functions().NtWaitForSingleObject)(Handle, Alertable, Timeout) }
}

/// Wrapper for the `NtCreateEvent` API.
#[inline(always)]
pub fn NtCreateEvent(
    EventHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut c_void,
    EventType: EVENT_TYPE,
    InitialState: u8,
) -> NTSTATUS {
    unsafe { 
        (functions().NtCreateEvent)(
            EventHandle, 
            DesiredAccess, 
            ObjectAttributes, 
            EventType, 
            InitialState
        ) 
    }
}

/// Wrapper for the `NtDuplicateObject` API.
#[inline(always)]
pub fn NtDuplicateObject(
    SourceProcessHandle: HANDLE,
    SourceHandle: HANDLE,
    TargetProcessHandle: HANDLE,
    TargetHandle: *mut HANDLE,
    DesiredAccess: u32,
    HandleAttributes: u32,
    Options: u32,
) -> NTSTATUS {
    unsafe {
        (functions().NtDuplicateObject)(
            SourceProcessHandle,
            SourceHandle,
            TargetProcessHandle,
            TargetHandle,
            DesiredAccess,
            HandleAttributes,
            Options,
        )
    }
}

/// Wrapper for the `NtLockVirtualMemory` API.
#[inline(always)]
pub fn NtLockVirtualMemory(
    ProcessHandle: HANDLE, 
    BaseAddress: *mut *mut c_void, 
    RegionSize: *mut usize, 
    MapType: u32
) -> NTSTATUS {
    unsafe { 
        (functions().NtLockVirtualMemory)(
            ProcessHandle, 
            BaseAddress, 
            RegionSize, 
            MapType
        ) 
    }
}

/// Wrapper for the `NtAllocateVirtualMemory` API.
pub fn NtAllocateVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    RegionSize: *mut usize,
    AllocationType: u32,
    Protect: u32,
) -> NTSTATUS {
    match syscall!(
        obf!("NtAllocateVirtualMemory"),
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect
    ) {
        Ok(ret) => ret as NTSTATUS,
        Err(_) => STATUS_UNSUCCESSFUL,
    }
}

/// Wrapper for the `NtProtectVirtualMemory` API.
pub fn NtProtectVirtualMemory(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    NewProtect: u32,
    OldProtect: *mut u32,
) -> NTSTATUS {
    match syscall!(
        obf!("NtProtectVirtualMemory"), 
        ProcessHandle, 
        BaseAddress, 
        RegionSize, 
        NewProtect, 
        OldProtect
    ) {
        Ok(ret) => ret as NTSTATUS,
        Err(_) => STATUS_UNSUCCESSFUL,
    }
}

/// Wrapper for the `NtQueryInformationProcess` API.
#[inline(always)]
pub fn NtQueryInformationProcess(
    ProcessHandle: HANDLE,
    ProcessInformationClass: u32,
    ProcessInformation: *mut c_void,
    ProcessInformationLength: u32,
    ReturnLength: *mut u32,
) -> NTSTATUS {
    unsafe {
        (functions().NtQueryInformationProcess)(
            ProcessHandle, 
            ProcessInformationClass, 
            ProcessInformation, 
            ProcessInformationLength, 
            ReturnLength
        )
    }
}

/// Wrapper for the `NtAlertResumeThread` API.
#[inline(always)]
pub fn NtAlertResumeThread(ThreadHandle: HANDLE, PreviousSuspendCount: *mut u32) -> NTSTATUS {
    unsafe { (functions().NtAlertResumeThread)(ThreadHandle, PreviousSuspendCount) }
}

/// Wrapper for the `NtQueueApcThread` API.
#[inline(always)]
pub fn NtQueueApcThread(
    ThreadHandle: HANDLE,
    ApcRoutine: *mut c_void,
    ApcArgument1: *mut c_void,
    ApcArgument2: *mut c_void,
    ApcArgument3: *mut c_void,
) -> NTSTATUS {
    unsafe { 
        (functions().NtQueueApcThread)(
            ThreadHandle, 
            ApcRoutine, 
            ApcArgument1, 
            ApcArgument2, 
            ApcArgument3
        ) 
    }
}

/// Wrapper for the `NtSignalAndWaitForSingleObject` API.
#[inline(always)]
pub fn NtSignalAndWaitForSingleObject(
    SignalHandle: HANDLE, 
    WaitHandle: HANDLE, 
    Alertable: u8, 
    Timeout: *mut LARGE_INTEGER
) -> NTSTATUS {
    unsafe { 
        (functions().NtSignalAndWaitForSingleObject)(
            SignalHandle, 
            WaitHandle, 
            Alertable, 
            Timeout
        ) 
    }
}

/// Wrapper for the `TpAllocPool` API.
#[inline(always)]
pub fn TpAllocPool(PoolReturn: *mut *mut c_void, Reserved: *mut c_void) -> NTSTATUS {
    unsafe { (functions().TpAllocPool)(PoolReturn, Reserved) }
}

/// Wrapper for the `TpSetPoolStackInformation` API.
#[inline(always)]
pub fn TpSetPoolStackInformation(
    Pool: *mut c_void, 
    PoolStackInformation: *mut TP_POOL_STACK_INFORMATION
) -> NTSTATUS {
    unsafe { (functions().TpSetPoolStackInformation)(Pool, PoolStackInformation) }
}

/// Wrapper for the `TpSetPoolMinThreads` API.
#[inline(always)]
pub fn TpSetPoolMinThreads(Pool: *mut c_void, MinThreads: u32) -> NTSTATUS {
    unsafe { (functions().TpSetPoolMinThreads)(Pool, MinThreads) }
}

/// Wrapper for the `TpSetPoolMaxThreads` API.
#[inline(always)]
pub fn TpSetPoolMaxThreads(Pool: *mut c_void, MaxThreads: u32) {
    unsafe { (functions().TpSetPoolMaxThreads)(Pool, MaxThreads) }
}

/// Wrapper for the `TpAllocTimer` API.
#[inline(always)]
pub fn TpAllocTimer(
    Timer: *mut *mut c_void, 
    Callback: *mut c_void, 
    Context: *mut c_void, 
    CallbackEnviron: *mut TP_CALLBACK_ENVIRON_V3
) -> NTSTATUS {
    unsafe { (functions().TpAllocTimer)(Timer, Callback, Context, CallbackEnviron) }
}

/// Wrapper for the `TpSetTimer` API.
#[inline(always)]
pub fn TpSetTimer(
    Timer: *mut c_void, 
    DueTime: *mut LARGE_INTEGER, 
    Period: u32, 
    WindowLength: u32
) {
    unsafe { 
        (functions().TpSetTimer)(Timer, DueTime, Period, WindowLength) 
    }
}

/// Wrapper for the `TpAllocWait` API.
#[inline(always)]
pub fn TpAllocWait(
    WaitReturn: *mut *mut c_void,
    Callback: *mut c_void,
    Context: *mut c_void,
    CallbackEnviron: *mut TP_CALLBACK_ENVIRON_V3,
) -> NTSTATUS {
    unsafe { (functions().TpAllocWait)(WaitReturn, Callback, Context, CallbackEnviron) }
}

/// Wrapper for the `TpSetWait` API.
#[inline(always)]
pub fn TpSetWait(Wait: *mut c_void, Handle: *mut c_void, Timeout: *mut LARGE_INTEGER) {
    unsafe { (functions().TpSetWait)(Wait, Handle, Timeout) }
}

/// Wrapper for the `CloseThreadpool` API.
#[inline(always)]
pub fn CloseThreadpool(Pool: *mut c_void) -> NTSTATUS {
    unsafe { (functions().CloseThreadpool)(Pool) }
}

/// Wrapper for the `RtlWalkHeap` API.
#[inline(always)]
pub fn RtlWalkHeap(HeapHandle: *mut c_void, Entry: *mut RTL_HEAP_WALK_ENTRY) -> NTSTATUS {
    unsafe { (functions().RtlWalkHeap)(HeapHandle, Entry) }
}

/// Wrapper for the `SetProcessValidCallTargets` API.
#[inline(always)]
pub fn SetProcessValidCallTargets(
    hProcess: HANDLE,
    VirtualAddress: *mut c_void,
    RegionSize: usize,
    NumberOfOffsets: u32,
    OffsetInformation: *mut CFG_CALL_TARGET_INFO,
) -> u8 {
    unsafe { 
        (functions().SetProcessValidCallTargets)(
            hProcess, 
            VirtualAddress, 
            RegionSize, 
            NumberOfOffsets, 
            OffsetInformation
        ) 
    }
}

/// Wrapper for the `ConvertFiberToThread` API.
#[inline(always)]
pub fn ConvertFiberToThread() -> i32 {
    unsafe { (functions().ConvertFiberToThread)() }
}

/// Wrapper for the `ConvertThreadToFiber` API.
#[inline(always)]
pub fn ConvertThreadToFiber(lpParameter: *mut c_void) -> *mut c_void {
    unsafe { (functions().ConvertThreadToFiber)(lpParameter) }
}

/// Wrapper for the `CreateFiber` API.
#[inline(always)]
pub fn CreateFiber(
    dwStackSize: usize, 
    lpStartAddress: LPFIBER_START_ROUTINE, 
    lpParameter: *const c_void
) -> *mut c_void {
    unsafe { (functions().CreateFiber)(dwStackSize, lpStartAddress, lpParameter) }
}

/// Wrapper for the `DeleteFiber` API.
#[inline(always)]
pub fn DeleteFiber(lpFiber: *mut c_void) {
    unsafe { (functions().DeleteFiber)(lpFiber) }
}

/// Wrapper for the `SwitchToFiber` API.
#[inline(always)]
pub fn SwitchToFiber(lpFiber: *mut c_void) {
    unsafe { (functions().SwitchToFiber)(lpFiber) }
}

/// Lightweight wrapper for `NtSetEvent`, used in a Threadpool callback context.
pub extern "C" fn NtSetEvent2(_: *mut c_void, event: *mut c_void, _: *mut c_void, _: u32) {
    NtSetEvent(event, null_mut());
}

/// Get current stack pointer (RSP)
#[inline(always)]
pub fn current_rsp() -> u64 {
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp) };
    rsp
}
