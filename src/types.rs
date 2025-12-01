use core::ffi::c_void;
use core::ptr::null_mut;
use dinvk::types::{EVENT_TYPE, HANDLE, LARGE_INTEGER, NTSTATUS};

pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u64 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u64 = 0x40;
pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;
pub const CONTEXT_FULL: u32 = 0x00010007;
pub const THREAD_ALL_ACCESS: u32 = 0x001F03FF;
pub const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;
pub const VM_LOCK_1: u32 = 0x0001;
pub const HEAP_GROWABLE: u32 = 0x00000002;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct EXTENDED_PROCESS_INFORMATION {
    pub ExtendedProcessInfo: u32,
    pub ExtendedProcessInfoBuffer: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TP_CALLBACK_ENVIRON_V3 {
    pub Version: u32,
    pub Pool: *mut c_void,
    pub CleanupGroup: *mut c_void,
    pub CleanupGroupCancelCallback: *mut c_void,
    pub RaceDll: *mut c_void,
    pub ActivationContext: isize,
    pub FinalizationCallback: *mut c_void,
    pub u: TP_CALLBACK_ENVIRON_V3_0,
    pub CallbackPriority: i32,
    pub Size: u32,
}

impl Default for TP_CALLBACK_ENVIRON_V3 {
    fn default() -> Self {
        Self {
            Version: 3,
            Pool: null_mut(),
            CleanupGroup: null_mut(),
            CleanupGroupCancelCallback: null_mut(),
            RaceDll: null_mut(),
            ActivationContext: 0,
            FinalizationCallback: null_mut(),
            u: TP_CALLBACK_ENVIRON_V3_0 { Flags: 0 },
            CallbackPriority: 1,
            Size: size_of::<TP_CALLBACK_ENVIRON_V3>() as u32,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TP_CALLBACK_ENVIRON_V3_0 {
    pub Flags: u32,
    pub s: TP_CALLBACK_ENVIRON_V3_0_0,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TP_CALLBACK_ENVIRON_V3_0_0 {
    pub _bitfield: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct TP_POOL_STACK_INFORMATION {
    pub StackReserve: usize,
    pub StackCommit: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_HEAP_WALK_ENTRY {
    pub DataAddress: *mut c_void,
    pub DataSize: usize,
    pub OverheadBytes: u8,
    pub SegmentIndex: u8,
    pub Flags: u16,
    pub Anonymous: RTL_HEAP_WALK_ENTRY_0,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union RTL_HEAP_WALK_ENTRY_0 {
    pub Block: RTL_HEAP_WALK_ENTRY_0_0,
    pub Segment: RTL_HEAP_WALK_ENTRY_0_0_0,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_HEAP_WALK_ENTRY_0_0 {
    pub Settable: usize,
    pub TagIndex: u16,
    pub AllocatorBackTraceIndex: u16,
    pub Reserved: [u16; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_HEAP_WALK_ENTRY_0_0_0 {
    pub CommittedSize: u32,
    pub UnCommittedSize: u32,
    pub FirstEntry: *mut c_void,
    pub LastEntry: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CFG_CALL_TARGET_INFO {
    pub Offset: usize,
    pub Flags: usize,
}

pub type LPFIBER_START_ROUTINE = Option<unsafe extern "system" fn(lpFiberParameter: *mut c_void)>;
pub type ConvertThreadToFiberFn = unsafe extern "system" fn(lpParameter: *mut c_void) -> *mut c_void;
pub type ConvertFiberToThreadFn = unsafe extern "system" fn() -> i32;
pub type SwitchToFiberFn = unsafe extern "system" fn(lpFiber: *mut c_void);
pub type DeleteFiberFn = unsafe extern "system" fn(lpFiber: *mut c_void);
pub type CreateFiberFn = unsafe extern "system" fn(
    dwStackSize: usize,
    lpStartAddress: LPFIBER_START_ROUTINE,
    lpParameter: *const c_void,
) -> *mut c_void;

pub type CloseThreadpoolFn = unsafe extern "system" fn(Pool: *mut c_void) -> NTSTATUS;
pub type TpAllocPoolFn = unsafe extern "system" fn(PoolReturn: *mut *mut c_void, Reserved: *mut c_void) -> NTSTATUS;
pub type TpSetPoolMaxThreadsFn = unsafe extern "system" fn(Pool: *mut c_void, MaxThreads: u32);
pub type TpSetPoolMinThreadsFn = unsafe extern "system" fn(Pool: *mut c_void, MinThreads: u32) -> NTSTATUS;
pub type TpSetWaitFn = unsafe extern "system" fn(Wait: *mut c_void, Handle: *mut c_void, Timeout: *mut LARGE_INTEGER);
pub type TpAllocFn = unsafe extern "system" fn(
    Timer: *mut *mut c_void,
    Callback: *mut c_void,
    Context: *mut c_void,
    CallbackEnviron: *mut TP_CALLBACK_ENVIRON_V3,
) -> NTSTATUS;

pub type TpSetPoolStackInformationFn = unsafe extern "system" fn(
    Pool: *mut c_void,
    PoolStackInformation: *mut TP_POOL_STACK_INFORMATION,
) -> NTSTATUS;

pub type TpSetTimerFn = unsafe extern "system" fn(
    Timer: *mut c_void,
    DueTime: *mut LARGE_INTEGER,
    Period: u32,
    WindowLength: u32,
);

pub type NtCloseFn = unsafe extern "system" fn(Handle: HANDLE) -> NTSTATUS;
pub type NtSetEventFn = unsafe extern "system" fn(hEvent: *mut c_void, PreviousState: *mut i32) -> NTSTATUS;
pub type NtCreateEventFn = unsafe extern "system" fn(
    EventHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut c_void,
    EventType: EVENT_TYPE,
    InitialState: u8,
) -> NTSTATUS;

pub type NtWaitForSingleObjectFn = unsafe extern "system" fn(
    Handle: HANDLE,
    Alertable: u8,
    Timeout: *mut i32,
) -> NTSTATUS;

pub type NtSignalAndWaitForSingleObjectFn = unsafe extern "system" fn(
    SignalHandle: HANDLE,
    WaitHandle: HANDLE,
    Alertable: u8,
    Timeout: *mut LARGE_INTEGER,
) -> NTSTATUS;

pub type NtAlertResumeThreadFn = unsafe extern "system" fn(
    ThreadHandle: HANDLE,
    PreviousSuspendCount: *mut u32,
) -> NTSTATUS;

pub type NtQueueApcThreadFn = unsafe extern "system" fn(
    ThreadHandle: HANDLE,
    ApcRoutine: *mut c_void,
    ApcArgument1: *mut c_void,
    ApcArgument2: *mut c_void,
    ApcArgument3: *mut c_void,
) -> NTSTATUS;

pub type NtQueryInformationProcessFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    ProcessInformationClass: u32,
    ProcessInformation: *mut c_void,
    ProcessInformationLength: u32,
    ReturnLength: *mut u32,
) -> NTSTATUS;

pub type NtDuplicateObjectFn = unsafe extern "system" fn(
    SourceProcessHandle: HANDLE,
    SourceHandle: HANDLE,
    TargetProcessHandle: HANDLE,
    TargetHandle: *mut HANDLE,
    DesiredAccess: u32,
    HandleAttributes: u32,
    Options: u32,
) -> NTSTATUS;

pub type NtLockVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    MapType: u32,
) -> NTSTATUS;

pub type RtlWalkHeapFn = unsafe extern "system" fn(
    HeapHandle: *mut c_void,
    Entry: *mut RTL_HEAP_WALK_ENTRY,
) -> NTSTATUS;

pub type SetProcessValidCallTargetsFn = unsafe extern "system" fn(
    hProcess: HANDLE,
    VirtualAddress: *mut c_void,
    RegionSize: usize,
    NumberOfOffsets: u32,
    OffsetInformation: *mut CFG_CALL_TARGET_INFO,
) -> u8;