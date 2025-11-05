// Copyright (c) 2025 joaoviictorti
// Licensed under the MIT License. See LICENSE file in the project root for details.

use alloc::string::String;
use core::{ffi::c_void, ptr::null_mut};

use obfstr::{obfstring as s};
use anyhow::{Context, Result, bail};
use dinvk::NtCurrentProcess;
use dinvk::{
    NT_SUCCESS,
    pe::PE,
};

use crate::data::{
    CFG_CALL_TARGET_INFO, 
    EXTENDED_PROCESS_INFORMATION
};
use crate::utils::{
    Config, 
    NtQueryInformationProcess, 
    SetProcessValidCallTargets
};

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
/// If CFG is enforced.
pub fn is_cfg_enforced() -> Result<bool> {
    let mut proc_info = EXTENDED_PROCESS_INFORMATION {
        ExtendedProcessInfo: ProcessControlFlowGuardPolicy as u32,
        ..Default::default()
    };

    let status = NtQueryInformationProcess(
        NtCurrentProcess(),
        PROCESS_COOKIE | PROCESS_USER_MODE_IOPL,
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
/// On success, or an error if the operation fails or CFG query fails.
pub fn add_cfg(module: usize, function: usize) -> Result<()> {
    unsafe {
        let nt_header = PE::parse(module as *mut c_void)
            .nt_header()
            .context(s!("Invalid NT header"))?;

        // Memory range to apply the CFG policy
        let size = ((*nt_header).OptionalHeader.SizeOfImage as usize + 0xFFF) & !0xFFF;

        // Describe the valid call target
        let mut cfg = CFG_CALL_TARGET_INFO {
            Flags: CFG_CALL_TARGET_VALID,
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
pub fn register_cfg_targets(cfg: &Config) {
    let targets = [(cfg.modules.ntdll, cfg.nt_continue)];
    for (module, func) in targets {
        if let Err(e) = add_cfg(module.as_u64() as usize, func.as_u64() as usize) {
            if cfg!(debug_assertions) {
                dinvk::println!("add_cfg failed: {e}");
            }
        }
    }
}