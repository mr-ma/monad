use std::{
    ffi::{c_char, c_int},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

use tiny_privacy_vm_confidential_backend::{
    CONFIDENTIAL_BACKEND_ID, ConfidentialTinyVmBackend, CryptoConfig, PublicBalanceChangeBundle,
    PublicBalanceChangeKind, TransferCall, assemble_public_balance_change_call,
    assemble_transfer_call, canonical_empty_commitment,
};
use tiny_privacy_vm_runtime::{TinyVmBackend, TinyVmOperation, decode_tinyvm_artifacts};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TinyVmBackendTransferPublicOut {
    pub token: [u8; 32],
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub sender_version: u64,
    pub recipient_version: u64,
    pub sender_old_commitment: [u8; 32],
    pub sender_new_commitment: [u8; 32],
    pub recipient_old_commitment: [u8; 32],
    pub recipient_new_commitment: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TinyVmBackendPublicBalanceChangePublicOut {
    pub kind: u8,
    pub token: [u8; 32],
    pub owner: [u8; 20],
    pub version: u64,
    pub public_amount: u64,
    pub old_commitment: [u8; 32],
    pub new_commitment: [u8; 32],
}

fn write_error(message: &str, error_buf: *mut c_char, error_len: usize) {
    if error_buf.is_null() || error_len == 0 {
        return;
    }

    let bytes = message.as_bytes();
    let copy_len = bytes.len().min(error_len.saturating_sub(1));

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), error_buf.cast::<u8>(), copy_len);
        *error_buf.add(copy_len) = 0;
    }
}

fn ffi_guard<F>(error_buf: *mut c_char, error_len: usize, f: F) -> c_int
where
    F: FnOnce() -> anyhow::Result<()>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => {
            write_error("", error_buf, error_len);
            1
        }
        Ok(Err(err)) => {
            write_error(&err.to_string(), error_buf, error_len);
            0
        }
        Err(_) => {
            write_error("tinyvm confidential ffi panicked", error_buf, error_len);
            0
        }
    }
}

fn transfer_public_out(call: &TransferCall) -> TinyVmBackendTransferPublicOut {
    let bundle = &call.bundle;
    TinyVmBackendTransferPublicOut {
        token: bundle.public.token,
        from: bundle.public.from,
        to: bundle.public.to,
        sender_version: bundle.public.sender_version,
        recipient_version: bundle.public.recipient_version,
        sender_old_commitment: bundle.public.sender_old_commitment.0,
        sender_new_commitment: bundle.public.sender_new_commitment.0,
        recipient_old_commitment: bundle.public.recipient_old_commitment.0,
        recipient_new_commitment: bundle.public.recipient_new_commitment.0,
    }
}

fn runtime_backend(backend_id: u32) -> anyhow::Result<ConfidentialTinyVmBackend> {
    anyhow::ensure!(
        backend_id == CONFIDENTIAL_BACKEND_ID,
        "unsupported tinyvm backend id {backend_id}"
    );
    Ok(ConfidentialTinyVmBackend)
}

fn verify_transfer_via_runtime_backend(
    backend_id: u32,
    tx_bytes: &[u8],
    artifacts_bytes: &[u8],
) -> anyhow::Result<TransferCall> {
    let artifacts = decode_tinyvm_artifacts(artifacts_bytes)?;
    let backend = runtime_backend(backend_id)?;
    backend.verify_call(TinyVmOperation::Transfer, tx_bytes, &artifacts)?;
    assemble_transfer_call(tx_bytes, &artifacts)
}

fn verify_public_balance_change_via_runtime_backend(
    backend_id: u32,
    tx_bytes: &[u8],
    artifacts_bytes: &[u8],
) -> anyhow::Result<PublicBalanceChangeBundle> {
    let artifacts = decode_tinyvm_artifacts(artifacts_bytes)?;
    let bundle = assemble_public_balance_change_call(tx_bytes, &artifacts)?;
    let operation = match bundle.public.kind {
        PublicBalanceChangeKind::Shield => TinyVmOperation::Shield,
        PublicBalanceChangeKind::Unshield => TinyVmOperation::Unshield,
    };
    let backend = runtime_backend(backend_id)?;
    backend.verify_call(operation, tx_bytes, &artifacts)?;
    Ok(bundle)
}

fn public_balance_change_out(
    bundle: &PublicBalanceChangeBundle,
) -> TinyVmBackendPublicBalanceChangePublicOut {
    TinyVmBackendPublicBalanceChangePublicOut {
        kind: match bundle.public.kind {
            PublicBalanceChangeKind::Shield => 0,
            PublicBalanceChangeKind::Unshield => 1,
        },
        token: bundle.public.token,
        owner: bundle.public.owner,
        version: bundle.public.version,
        public_amount: bundle.public.public_amount,
        old_commitment: bundle.public.old_commitment.0,
        new_commitment: bundle.public.new_commitment.0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tinyvm_verify_transfer_backend_call(
    backend_id: u32,
    tx_bytes_ptr: *const u8,
    tx_bytes_len: usize,
    artifacts_ptr: *const u8,
    artifacts_len: usize,
    out_public: *mut TinyVmBackendTransferPublicOut,
    error_buf: *mut c_char,
    error_len: usize,
) -> c_int {
    ffi_guard(error_buf, error_len, || {
        anyhow::ensure!(!out_public.is_null(), "output pointer is null");
        anyhow::ensure!(!tx_bytes_ptr.is_null(), "tx bytes pointer is null");
        anyhow::ensure!(!artifacts_ptr.is_null(), "artifacts pointer is null");

        let tx_bytes = unsafe { slice::from_raw_parts(tx_bytes_ptr, tx_bytes_len) };
        let artifacts = unsafe { slice::from_raw_parts(artifacts_ptr, artifacts_len) };
        let call = verify_transfer_via_runtime_backend(backend_id, tx_bytes, artifacts)?;
        unsafe {
            *out_public = transfer_public_out(&call);
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tinyvm_verify_public_balance_change_backend_call(
    backend_id: u32,
    tx_bytes_ptr: *const u8,
    tx_bytes_len: usize,
    artifacts_ptr: *const u8,
    artifacts_len: usize,
    out_public: *mut TinyVmBackendPublicBalanceChangePublicOut,
    error_buf: *mut c_char,
    error_len: usize,
) -> c_int {
    ffi_guard(error_buf, error_len, || {
        anyhow::ensure!(!out_public.is_null(), "output pointer is null");
        anyhow::ensure!(!tx_bytes_ptr.is_null(), "tx bytes pointer is null");
        anyhow::ensure!(!artifacts_ptr.is_null(), "artifacts pointer is null");

        let tx_bytes = unsafe { slice::from_raw_parts(tx_bytes_ptr, tx_bytes_len) };
        let artifacts = unsafe { slice::from_raw_parts(artifacts_ptr, artifacts_len) };
        let bundle =
            verify_public_balance_change_via_runtime_backend(backend_id, tx_bytes, artifacts)?;
        unsafe {
            *out_public = public_balance_change_out(&bundle);
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tinyvm_backend_empty_commitment(
    backend_id: u32,
    out_commitment: *mut u8,
) -> c_int {
    if out_commitment.is_null() {
        return 0;
    }
    if runtime_backend(backend_id).is_err() {
        return 0;
    }
    let commitment = canonical_empty_commitment(&CryptoConfig::default());
    unsafe {
        ptr::copy_nonoverlapping(commitment.0.as_ptr(), out_commitment, commitment.0.len());
    }
    1
}
