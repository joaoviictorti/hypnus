use core::{ffi::c_void, mem::transmute, ptr::null_mut};
use spin::Once;
use uwd::syscall;
use obfstr::{obfstr as s};
use dinvk::hash::{jenkins3, murmur3};
use dinvk::types::{EVENT_TYPE, HANDLE};
use dinvk::types::{LARGE_INTEGER, NTSTATUS}; 
use dinvk::types::STATUS_UNSUCCESSFUL;
use dinvk::module::{
    get_module_address,
    get_proc_address,
    get_ntdll_address
};

use crate::types::*;

/// One-time initialization of the structure with resolved pointers.
static WINAPIS: Once<Winapis> = Once::new();

/// Windows DLLs required during initialization.
#[derive(Debug, Clone, Copy, Default)]
pub struct Modules {
    pub ntdll: Dll,
    pub kernel32: Dll,
    pub cryptbase: Dll,
    pub kernelbase: Dll,
}

/// Wrapper for DLL base addresses stored as `u64`.
#[derive(Default, Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Dll(u64);

impl Dll {
    /// Returns the address as a mutable pointer.
    #[inline]
    pub fn as_ptr(self) -> *mut c_void {
        self.0 as *mut c_void
    }

    /// Returns the address as a `u64`.
    #[inline]
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
    #[inline]
    pub fn as_ptr(self) -> *const c_void {
        self.0 as *const c_void
    }

    /// Returns the pointer as a mutable `*mut c_void`.
    #[inline]
    pub fn as_mut_ptr(self) -> *mut c_void {
        self.0 as *mut c_void
    }

    /// Returns true if the pointer is null.
    #[inline]
    pub fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Returns the address as a `u64`.
    #[inline]
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
pub struct Winapis {
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

/// Returns a reference to the resolved winapis structure.
#[inline]
pub fn winapis() -> &'static Winapis {
    WINAPIS.call_once(|| {
        let ntdll = get_ntdll_address();
        let kernelbase = get_module_address(2737729883u32, Some(murmur3));
        let kernel32 = get_module_address(2808682670u32, Some(murmur3));
        unsafe {
            Winapis {
                NtSignalAndWaitForSingleObject: transmute(get_proc_address(ntdll, 2343758301u32, Some(jenkins3))),
                NtQueueApcThread: transmute(get_proc_address(ntdll, 2047395029u32, Some(jenkins3))),
                NtAlertResumeThread: transmute(get_proc_address(ntdll, 3894675502u32, Some(jenkins3))),
                NtQueryInformationProcess: transmute(get_proc_address(ntdll, 2237456582u32, Some(jenkins3))),
                NtLockVirtualMemory: transmute(get_proc_address(ntdll, 4166947453u32, Some(jenkins3))),
                NtDuplicateObject: transmute(get_proc_address(ntdll, 2175435662u32, Some(jenkins3))),
                NtCreateEvent: transmute(get_proc_address(ntdll, 1593028964u32, Some(jenkins3))),
                NtWaitForSingleObject: transmute(get_proc_address(ntdll, 2606513692u32, Some(jenkins3))),
                NtClose: transmute(get_proc_address(ntdll, 3317382880u32, Some(jenkins3))),
                TpAllocPool: transmute(get_proc_address(ntdll, 2447693371u32, Some(jenkins3))),
                TpSetPoolStackInformation: transmute(get_proc_address(ntdll, 602502226u32, Some(jenkins3))),
                TpSetPoolMinThreads: transmute(get_proc_address(ntdll, 719914357u32, Some(jenkins3))),
                TpSetPoolMaxThreads: transmute(get_proc_address(ntdll, 2333365797u32, Some(jenkins3))),
                TpAllocTimer: transmute(get_proc_address(ntdll, 2608438500u32, Some(jenkins3))),
                TpSetTimer: transmute(get_proc_address(ntdll, 3984996346u32, Some(jenkins3))),
                TpAllocWait: transmute(get_proc_address(ntdll, 1490509702u32, Some(jenkins3))),
                TpSetWait: transmute(get_proc_address(ntdll, 47310713u32, Some(jenkins3))),
                NtSetEvent: transmute(get_proc_address(ntdll, 1943906260u32, Some(jenkins3))),
                CloseThreadpool: transmute(get_proc_address(kernel32, 4211127317u32, Some(jenkins3))),
                RtlWalkHeap: transmute(get_proc_address(ntdll, 428298494u32, Some(jenkins3))),
                SetProcessValidCallTargets: transmute(get_proc_address(kernelbase, 2887664134u32, Some(jenkins3))),
                ConvertFiberToThread: transmute(get_proc_address(kernelbase, 3102155314u32, Some(jenkins3))),
                ConvertThreadToFiber: transmute(get_proc_address(kernelbase, 3394836561u32, Some(jenkins3))),
                CreateFiber: transmute(get_proc_address(kernelbase, 620670734u32, Some(jenkins3))),
                DeleteFiber: transmute(get_proc_address(kernelbase, 1500260625u32, Some(jenkins3))),
                SwitchToFiber: transmute(get_proc_address(kernelbase, 954746181u32, Some(jenkins3))),
            }
        }
    })
}

/// Wrapper for the `NtClose` API.
#[inline]
pub fn NtClose(Handle: HANDLE) -> NTSTATUS {
    unsafe { (winapis().NtClose)(Handle) }
}

/// Wrapper for the `NtSetEvent` API.
#[inline]
pub fn NtSetEvent(hEvent: *mut c_void, PreviousState: *mut i32) -> NTSTATUS {
    unsafe { (winapis().NtSetEvent)(hEvent, PreviousState) }
}

/// Wrapper for the `NtWaitForSingleObject` API.
#[inline]
pub fn NtWaitForSingleObject(Handle: HANDLE, Alertable: u8, Timeout: *mut i32) -> NTSTATUS {
    unsafe { (winapis().NtWaitForSingleObject)(Handle, Alertable, Timeout) }
}

/// Wrapper for the `NtCreateEvent` API.
#[inline]
pub fn NtCreateEvent(
    EventHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut c_void,
    EventType: EVENT_TYPE,
    InitialState: u8,
) -> NTSTATUS {
    unsafe { 
        (winapis().NtCreateEvent)(
            EventHandle, 
            DesiredAccess, 
            ObjectAttributes, 
            EventType, 
            InitialState
        ) 
    }
}

/// Wrapper for the `NtDuplicateObject` API.
#[inline]
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
        (winapis().NtDuplicateObject)(
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
#[inline]
pub fn NtLockVirtualMemory(
    ProcessHandle: HANDLE, 
    BaseAddress: *mut *mut c_void, 
    RegionSize: *mut usize, 
    MapType: u32
) -> NTSTATUS {
    unsafe { 
        (winapis().NtLockVirtualMemory)(
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
        s!("NtAllocateVirtualMemory"),
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
        s!("NtProtectVirtualMemory"), 
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
#[inline]
pub fn NtQueryInformationProcess(
    ProcessHandle: HANDLE,
    ProcessInformationClass: u32,
    ProcessInformation: *mut c_void,
    ProcessInformationLength: u32,
    ReturnLength: *mut u32,
) -> NTSTATUS {
    unsafe {
        (winapis().NtQueryInformationProcess)(
            ProcessHandle, 
            ProcessInformationClass, 
            ProcessInformation, 
            ProcessInformationLength, 
            ReturnLength
        )
    }
}

/// Wrapper for the `NtAlertResumeThread` API.
#[inline]
pub fn NtAlertResumeThread(ThreadHandle: HANDLE, PreviousSuspendCount: *mut u32) -> NTSTATUS {
    unsafe { (winapis().NtAlertResumeThread)(ThreadHandle, PreviousSuspendCount) }
}

/// Wrapper for the `NtQueueApcThread` API.
#[inline]
pub fn NtQueueApcThread(
    ThreadHandle: HANDLE,
    ApcRoutine: *mut c_void,
    ApcArgument1: *mut c_void,
    ApcArgument2: *mut c_void,
    ApcArgument3: *mut c_void,
) -> NTSTATUS {
    unsafe { 
        (winapis().NtQueueApcThread)(
            ThreadHandle, 
            ApcRoutine, 
            ApcArgument1, 
            ApcArgument2, 
            ApcArgument3
        ) 
    }
}

/// Wrapper for the `NtSignalAndWaitForSingleObject` API.
#[inline]
pub fn NtSignalAndWaitForSingleObject(
    SignalHandle: HANDLE, 
    WaitHandle: HANDLE, 
    Alertable: u8, 
    Timeout: *mut LARGE_INTEGER
) -> NTSTATUS {
    unsafe { 
        (winapis().NtSignalAndWaitForSingleObject)(
            SignalHandle, 
            WaitHandle, 
            Alertable, 
            Timeout
        ) 
    }
}

/// Wrapper for the `TpAllocPool` API.
#[inline]
pub fn TpAllocPool(PoolReturn: *mut *mut c_void, Reserved: *mut c_void) -> NTSTATUS {
    unsafe { (winapis().TpAllocPool)(PoolReturn, Reserved) }
}

/// Wrapper for the `TpSetPoolStackInformation` API.
#[inline]
pub fn TpSetPoolStackInformation(
    Pool: *mut c_void, 
    PoolStackInformation: *mut TP_POOL_STACK_INFORMATION
) -> NTSTATUS {
    unsafe { (winapis().TpSetPoolStackInformation)(Pool, PoolStackInformation) }
}

/// Wrapper for the `TpSetPoolMinThreads` API.
#[inline]
pub fn TpSetPoolMinThreads(Pool: *mut c_void, MinThreads: u32) -> NTSTATUS {
    unsafe { (winapis().TpSetPoolMinThreads)(Pool, MinThreads) }
}

/// Wrapper for the `TpSetPoolMaxThreads` API.
#[inline]
pub fn TpSetPoolMaxThreads(Pool: *mut c_void, MaxThreads: u32) {
    unsafe { (winapis().TpSetPoolMaxThreads)(Pool, MaxThreads) }
}

/// Wrapper for the `TpAllocTimer` API.
#[inline]
pub fn TpAllocTimer(
    Timer: *mut *mut c_void, 
    Callback: *mut c_void, 
    Context: *mut c_void, 
    CallbackEnviron: *mut TP_CALLBACK_ENVIRON_V3
) -> NTSTATUS {
    unsafe { (winapis().TpAllocTimer)(Timer, Callback, Context, CallbackEnviron) }
}

/// Wrapper for the `TpSetTimer` API.
#[inline]
pub fn TpSetTimer(
    Timer: *mut c_void, 
    DueTime: *mut LARGE_INTEGER, 
    Period: u32, 
    WindowLength: u32
) {
    unsafe { 
        (winapis().TpSetTimer)(Timer, DueTime, Period, WindowLength) 
    }
}

/// Wrapper for the `TpAllocWait` API.
#[inline]
pub fn TpAllocWait(
    WaitReturn: *mut *mut c_void,
    Callback: *mut c_void,
    Context: *mut c_void,
    CallbackEnviron: *mut TP_CALLBACK_ENVIRON_V3,
) -> NTSTATUS {
    unsafe { (winapis().TpAllocWait)(WaitReturn, Callback, Context, CallbackEnviron) }
}

/// Wrapper for the `TpSetWait` API.
#[inline]
pub fn TpSetWait(Wait: *mut c_void, Handle: *mut c_void, Timeout: *mut LARGE_INTEGER) {
    unsafe { (winapis().TpSetWait)(Wait, Handle, Timeout) }
}

/// Wrapper for the `CloseThreadpool` API.
#[inline]
pub fn CloseThreadpool(Pool: *mut c_void) -> NTSTATUS {
    unsafe { (winapis().CloseThreadpool)(Pool) }
}

/// Wrapper for the `RtlWalkHeap` API.
#[inline]
pub fn RtlWalkHeap(HeapHandle: *mut c_void, Entry: *mut RTL_HEAP_WALK_ENTRY) -> NTSTATUS {
    unsafe { (winapis().RtlWalkHeap)(HeapHandle, Entry) }
}

/// Wrapper for the `SetProcessValidCallTargets` API.
#[inline]
pub fn SetProcessValidCallTargets(
    hProcess: HANDLE,
    VirtualAddress: *mut c_void,
    RegionSize: usize,
    NumberOfOffsets: u32,
    OffsetInformation: *mut CFG_CALL_TARGET_INFO,
) -> u8 {
    unsafe { 
        (winapis().SetProcessValidCallTargets)(
            hProcess, 
            VirtualAddress, 
            RegionSize, 
            NumberOfOffsets, 
            OffsetInformation
        ) 
    }
}

/// Wrapper for the `ConvertFiberToThread` API.
#[inline]
pub fn ConvertFiberToThread() -> i32 {
    unsafe { (winapis().ConvertFiberToThread)() }
}

/// Wrapper for the `ConvertThreadToFiber` API.
#[inline]
pub fn ConvertThreadToFiber(lpParameter: *mut c_void) -> *mut c_void {
    unsafe { (winapis().ConvertThreadToFiber)(lpParameter) }
}

/// Wrapper for the `CreateFiber` API.
#[inline]
pub fn CreateFiber(
    dwStackSize: usize, 
    lpStartAddress: LPFIBER_START_ROUTINE, 
    lpParameter: *const c_void
) -> *mut c_void {
    unsafe { (winapis().CreateFiber)(dwStackSize, lpStartAddress, lpParameter) }
}

/// Wrapper for the `DeleteFiber` API.
#[inline]
pub fn DeleteFiber(lpFiber: *mut c_void) {
    unsafe { (winapis().DeleteFiber)(lpFiber) }
}

/// Wrapper for the `SwitchToFiber` API.
#[inline]
pub fn SwitchToFiber(lpFiber: *mut c_void) {
    unsafe { (winapis().SwitchToFiber)(lpFiber) }
}

/// Lightweight wrapper for `NtSetEvent`, used in a Threadpool callback context.
pub extern "C" fn NtSetEvent2(_: *mut c_void, event: *mut c_void, _: *mut c_void, _: u32) {
    NtSetEvent(event, null_mut());
}