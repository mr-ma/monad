//! TinyVM generic FFI bridge.
//!
//! Single entry point `tinyvm_apply` that delegates to the Rust backend registry.
//! The C++ precompile calls this; Rust drives state reads/writes via callbacks.

use std::ffi::c_void;
use std::slice;

use tiny_privacy_vm_confidential_backend::ConfidentialTinyVmBackend;
use tiny_privacy_vm_runtime::{
    TinyVmBackend, TinyVmRegistry, TinyVmStateStore, TinyVmTxContext,
};

// ── Callback-backed store ───────────────────────────────────────────────────

type StoreGetFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    key: *const u8, key_len: usize,
    value_buf: *mut u8, value_buf_len: usize,
    value_len: *mut usize,
) -> i32;

type StoreSetFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    key: *const u8, key_len: usize,
    value: *const u8, value_len: usize,
);

struct FfiStore {
    ctx: *mut c_void,
    get_fn: StoreGetFn,
    set_fn: StoreSetFn,
}

impl TinyVmStateStore for FfiStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 4096];
        let mut len: usize = 0;
        let rc = unsafe {
            (self.get_fn)(
                self.ctx,
                key.as_ptr(), key.len(),
                buf.as_mut_ptr(), buf.len(),
                &mut len,
            )
        };
        if rc != 1 || len == 0 {
            return None;
        }
        buf.truncate(len);
        // Check if all zeros (EVM default = not set)
        if buf.iter().all(|&b| b == 0) {
            return None;
        }
        Some(buf)
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        unsafe {
            (self.set_fn)(
                self.ctx,
                key.as_ptr(), key.len(),
                value.as_ptr(), value.len(),
            );
        }
    }
}

// ── Result struct ───────────────────────────────────────────────────────────

#[repr(C)]
pub struct TinyVmApplyResult {
    pub escrow_delta: i64,
    pub token: [u8; 32],
    pub owner: [u8; 20],
    pub success: u8,
}

// ── Registry ────────────────────────────────────────────────────────────────

fn registry() -> TinyVmRegistry<'static> {
    static BACKEND: ConfidentialTinyVmBackend = ConfidentialTinyVmBackend;
    static BACKENDS: [&dyn TinyVmBackend; 1] = [&BACKEND];
    TinyVmRegistry::new(&BACKENDS)
}

// ── FFI entry points ────────────────────────────────────────────────────────

/// Returns gas cost for the given TinyVM call input, or 0 on decode failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tinyvm_gas_cost(
    input: *const u8, input_len: usize,
) -> u64 {
    let input_slice = unsafe { slice::from_raw_parts(input, input_len) };
    registry().gas_cost(input_slice).unwrap_or(0)
}

/// Generic TinyVM entry point called by the C++ precompile.
/// Decodes envelope, dispatches to backend, verifies + applies state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tinyvm_apply(
    sender: *const u8, sender_len: usize,
    tx_value: u64,
    input: *const u8, input_len: usize,
    store_ctx: *mut c_void,
    store_get: StoreGetFn,
    store_set: StoreSetFn,
    result: *mut TinyVmApplyResult,
    error_buf: *mut u8, error_len: usize,
) -> i32 {
    let sender_slice = unsafe { slice::from_raw_parts(sender, sender_len) };
    let input_slice = unsafe { slice::from_raw_parts(input, input_len) };

    let mut sender_arr = [0u8; 20];
    if sender_len >= 20 {
        sender_arr.copy_from_slice(&sender_slice[..20]);
    }

    let ctx = TinyVmTxContext {
        sender: sender_arr,
        tx_value,
    };

    let mut store = FfiStore {
        ctx: store_ctx,
        get_fn: store_get,
        set_fn: store_set,
    };

    match registry().apply_input(&ctx, input_slice, &mut store) {
        Ok(_decoded) => {
            // TODO: extract escrow_delta from the backend's state changes.
            // For now, the backend handles escrow internally via the store.
            // The C++ side needs to know the balance transfer amount for
            // unshield. This will be addressed when MRC20 support lands.
            // Shield works because msg.value already moves MON via EVM CALL.
            unsafe {
                (*result).success = 1;
                (*result).escrow_delta = 0;
            }
            1
        }
        Err(err) => {
            let msg = format!("{err:#}");
            let bytes = msg.as_bytes();
            let copy_len = bytes.len().min(error_len.saturating_sub(1));
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), error_buf, copy_len);
                *error_buf.add(copy_len) = 0;
                (*result).success = 0;
            }
            0
        }
    }
}
