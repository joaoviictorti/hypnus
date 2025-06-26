use core::mem::transmute;
use core::ffi::c_void;

use spin::Once;
use obfstr::obfstr as s;
use dinvk::{GetModuleHandle, GetProcAddress};
use dinvk::{data::*, get_ntdll_address, hash::*};

use crate::data::*;

/// One-time initialization of the structure with resolved pointers.
static FUNCTIONS: Once<Functions> = Once::new();

/// Structure containing all function pointers resolved only once.
pub struct Functions {
    pub NtSignalAndWaitForSingleObject: NtSignalAndWaitForSingleObjectType,
    pub NtQueueApcThread: NtQueueApcThreadType,
    pub NtAlertResumeThread: NtAlertResumeThreadType,
    pub NtQueryInformationProcess: NtQueryInformationProcessType,
    pub NtLockVirtualMemory: NtLockVirtualMemoryType,
    pub NtDuplicateObject: NtDuplicateObjectType,
    pub NtCreateEvent: NtCreateEventType,
    pub NtWaitForSingleObject: NtWaitForSingleObjectType,
    pub NtClose: NtCloseType,
    pub TpAllocPool: TpAllocPoolType,
    pub TpSetPoolStackInformation: TpSetPoolStackInformationType,
    pub TpSetPoolMinThreads: TpSetPoolMinThreadsType,
    pub TpSetPoolMaxThreads: TpSetPoolMaxThreadsType,
    pub TpAllocTimer: TpAllocType,
    pub TpSetTimer: TpSetTimerType,
    pub TpAllocWait: TpAllocType,
    pub TpSetWait: TpSetWaitType,
    pub NtSetEvent: NtSetEventType,
    pub CloseThreadpool: CloseThreadpoolType,
    pub RtlWalkHeap: RtlWalkHeapType,
    pub SetProcessValidCallTargets: SetProcessValidCallTargetsType,
    pub ConvertFiberToThread: ConvertFiberToThreadType,
    pub ConvertThreadToFiber: ConvertThreadToFiberType,
    pub CreateFiber: CreateFiberType,
    pub DeleteFiber: DeleteFiberType,
    pub SwitchToFiber: SwitchToFiberType,
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
    unsafe { (functions().NtCreateEvent)(EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState) }
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
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS {
    match uwd::syscall!(
        s!("NtAllocateVirtualMemory"),
        process_handle,
        base_address,
        zero_bits,
        region_size,
        allocation_type,
        protect
    ) {
        Ok(ret) => ret as NTSTATUS,
        Err(_) => STATUS_UNSUCCESSFUL,
    }
}

/// Wrapper for the `NtProtectVirtualMemory` API.
pub fn NtProtectVirtualMemory(
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS {
    match uwd::syscall!(
        s!("NtProtectVirtualMemory"), 
        process_handle, 
        base_address, 
        region_size, 
        new_protect, 
        old_protect
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
    unsafe { (functions().NtQueueApcThread)(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3) }
}

/// Wrapper for the `NtSignalAndWaitForSingleObject` API.
#[inline(always)]
pub fn NtSignalAndWaitForSingleObject(
    SignalHandle: HANDLE, 
    WaitHandle: HANDLE, 
    Alertable: u8, 
    Timeout: *mut LARGE_INTEGER
) -> NTSTATUS {
    unsafe { (functions().NtSignalAndWaitForSingleObject)(SignalHandle, WaitHandle, Alertable, Timeout) }
}

/// Wrapper for the `TpAllocPool` API.
#[inline(always)]
pub fn TpAllocPool(PoolReturn: *mut *mut c_void, Reserved: *mut c_void) -> NTSTATUS {
    unsafe { (functions().TpAllocPool)(PoolReturn, Reserved) }
}

/// Wrapper for the `TpSetPoolStackInformation` API.
#[inline(always)]
pub fn TpSetPoolStackInformation(Pool: *mut c_void, PoolStackInformation: *mut TP_POOL_STACK_INFORMATION) -> NTSTATUS {
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
pub fn TpSetTimer(Timer: *mut c_void, DueTime: *mut LARGE_INTEGER, Period: u32, WindowLength: u32) {
    unsafe { (functions().TpSetTimer)(Timer, DueTime, Period, WindowLength) }
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
    unsafe { 
        (functions().CreateFiber)(
            dwStackSize, 
            lpStartAddress, 
            lpParameter
        ) 
    }
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
