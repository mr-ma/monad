//! TinyVM generic FFI bridge.
//!
//! Single entry point `tinyvm_apply` that delegates to the Rust backend registry.
//! The C++ precompile calls this; Rust drives state reads/writes via callbacks.

use std::ffi::c_void;
use std::slice;

use anyhow::{anyhow, ensure};
use tiny_privacy_vm_confidential_backend::ConfidentialTinyVmBackend;
use tiny_privacy_vm_confidential_backend::CONFIDENTIAL_BACKEND_ID;
use tiny_privacy_vm_runtime::{
    TinyVmArtifact, TinyVmBackend, TinyVmCall, TinyVmOperation, TinyVmRegistry,
    TinyVmStateStore, TinyVmTokenRegistration, TinyVmTxContext,
    TINYVM_CALL_MAGIC, decode_tinyvm_artifacts, encode_tinyvm_call,
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

// ── ABI compatibility bridge ───────────────────────────────────────────────

const REGISTER_TOKEN_SELECTOR: [u8; 4] = [0x2d, 0xed, 0x0f, 0xb5];
const SHIELD_PUBLIC_SELECTOR: [u8; 4] = [0xaf, 0xac, 0xd7, 0x77];
const TRANSFER_CONFIDENTIAL_SELECTOR: [u8; 4] = [0xf2, 0x4b, 0xf2, 0x0e];
const UNSHIELD_PUBLIC_SELECTOR: [u8; 4] = [0x5b, 0xd2, 0x62, 0xb4];

fn decode_abi_usize(word: &[u8]) -> anyhow::Result<usize> {
    ensure!(word.len() == 32, "abi word must be 32 bytes");
    ensure!(word[..24].iter().all(|b| *b == 0), "abi integer too large");

    let mut low = [0u8; 8];
    low.copy_from_slice(&word[24..32]);
    Ok(u64::from_be_bytes(low) as usize)
}

fn decode_abi_bytes(args: &[u8], offset: usize) -> anyhow::Result<Vec<u8>> {
    ensure!(offset + 32 <= args.len(), "abi offset out of range");

    let len = decode_abi_usize(&args[offset..offset + 32])?;
    let data_offset = offset + 32;
    let padded_len = len
        .checked_add(31)
        .ok_or_else(|| anyhow!("abi length overflow"))?
        / 32
        * 32;

    ensure!(data_offset + padded_len <= args.len(), "abi bytes truncated");
    Ok(args[data_offset..data_offset + len].to_vec())
}

fn decode_abi_two_bytes(args: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    ensure!(args.len() >= 64, "abi head too short");

    let first_offset = decode_abi_usize(&args[..32])?;
    let second_offset = decode_abi_usize(&args[32..64])?;

    Ok((
        decode_abi_bytes(args, first_offset)?,
        decode_abi_bytes(args, second_offset)?,
    ))
}

fn encode_internal_call(
    operation: TinyVmOperation,
    public_args: Vec<u8>,
    artifacts: Vec<TinyVmArtifact>,
) -> Vec<u8> {
    encode_tinyvm_call(&TinyVmCall {
        backend_id: CONFIDENTIAL_BACKEND_ID,
        operation,
        public_args,
        artifacts,
    })
}

fn normalize_detached_abi_call(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(input.len() >= 4, "payload shorter than selector");

    let selector: [u8; 4] = input[..4]
        .try_into()
        .expect("slice length checked above");
    let args = &input[4..];

    match selector {
        REGISTER_TOKEN_SELECTOR => {
            ensure!(args.len() >= 64, "registerToken args too short");
            ensure!(
                args[32..44].iter().all(|b| *b == 0),
                "registerToken address must be left-padded"
            );

            let mut token = [0u8; 32];
            token.copy_from_slice(&args[..32]);

            let mut public_asset = [0u8; 20];
            public_asset.copy_from_slice(&args[44..64]);

            let public_args = bincode::serialize(&TinyVmTokenRegistration {
                token,
                public_asset,
            })?;
            Ok(encode_internal_call(
                TinyVmOperation::RegisterToken,
                public_args,
                vec![],
            ))
        }
        SHIELD_PUBLIC_SELECTOR => {
            let (tx_bytes, artifacts_bytes) = decode_abi_two_bytes(args)?;
            let artifacts = decode_tinyvm_artifacts(&artifacts_bytes)?;
            Ok(encode_internal_call(
                TinyVmOperation::Shield,
                tx_bytes,
                artifacts,
            ))
        }
        TRANSFER_CONFIDENTIAL_SELECTOR => {
            let (tx_bytes, artifacts_bytes) = decode_abi_two_bytes(args)?;
            let artifacts = decode_tinyvm_artifacts(&artifacts_bytes)?;
            Ok(encode_internal_call(
                TinyVmOperation::Transfer,
                tx_bytes,
                artifacts,
            ))
        }
        UNSHIELD_PUBLIC_SELECTOR => {
            let (tx_bytes, artifacts_bytes) = decode_abi_two_bytes(args)?;
            let artifacts = decode_tinyvm_artifacts(&artifacts_bytes)?;
            Ok(encode_internal_call(
                TinyVmOperation::Unshield,
                tx_bytes,
                artifacts,
            ))
        }
        _ => Err(anyhow!("unknown tinyvm selector")),
    }
}

fn normalize_input(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    if input.starts_with(&TINYVM_CALL_MAGIC) {
        return Ok(input.to_vec());
    }

    normalize_detached_abi_call(input)
}

// ── FFI entry points ────────────────────────────────────────────────────────

/// Returns gas cost for the given TinyVM call input, or 0 on decode failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tinyvm_gas_cost(
    input: *const u8, input_len: usize,
) -> u64 {
    let input_slice = unsafe { slice::from_raw_parts(input, input_len) };
    let normalized = match normalize_input(input_slice) {
        Ok(normalized) => normalized,
        Err(_) => return 0,
    };
    registry().gas_cost(&normalized).unwrap_or(0)
}

/// Generic TinyVM entry point called by the C++ precompile.
/// Decodes envelope, dispatches to backend, verifies + applies state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tinyvm_apply(
    sender: *const u8, sender_len: usize,
    tx_value_lo: u64, tx_value_hi: u64,
    input: *const u8, input_len: usize,
    store_ctx: *mut c_void,
    store_get: StoreGetFn,
    store_set: StoreSetFn,
    result: *mut TinyVmApplyResult,
    error_buf: *mut u8, error_len: usize,
) -> i32 {
    let sender_slice = unsafe { slice::from_raw_parts(sender, sender_len) };
    let input_slice = unsafe { slice::from_raw_parts(input, input_len) };
    let normalized_input = match normalize_input(input_slice) {
        Ok(normalized) => normalized,
        Err(err) => {
            let msg = format!("{err:#}");
            let bytes = msg.as_bytes();
            let copy_len = bytes.len().min(error_len.saturating_sub(1));
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), error_buf, copy_len);
                *error_buf.add(copy_len) = 0;
                (*result).success = 0;
            }
            return 0;
        }
    };

    let mut sender_arr = [0u8; 20];
    if sender_len >= 20 {
        sender_arr.copy_from_slice(&sender_slice[..20]);
    }

    let ctx = TinyVmTxContext {
        sender: sender_arr,
        tx_value: (tx_value_lo as u128) | ((tx_value_hi as u128) << 64),
    };

    let mut store = FfiStore {
        ctx: store_ctx,
        get_fn: store_get,
        set_fn: store_set,
    };

    match registry().apply_input(&ctx, &normalized_input, &mut store) {
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

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use tiny_privacy_vm_confidential_backend::{
        CryptoConfig, native_mon_public_asset,
        new_empty_local_account, prove_shield_public,
        prove_transfer_with_sidecars, prove_unshield_public,
        apply_encrypted_recipient_memo, generate_auditor_keypair,
        serialize_public_balance_change_tx_bytes,
        serialize_public_balance_change_artifacts,
        serialize_transfer_tx_bytes, serialize_transfer_artifacts,
        AccountState,
    };
    use tiny_privacy_vm_runtime::encode_tinyvm_artifacts;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// ABI-encode two bytes values: abi.encode(bytes, bytes)
    fn abi_encode_two_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        fn pad32(len: usize) -> usize { ((len + 31) / 32) * 32 }
        fn word(val: usize) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&(val as u64).to_be_bytes());
            w
        }

        let a_padded = pad32(a.len());
        let b_padded = pad32(b.len());

        // offset_a = 64 (two words of head)
        // offset_b = 64 + 32 + a_padded
        let offset_a = 64usize;
        let offset_b = offset_a + 32 + a_padded;

        let mut out = Vec::new();
        out.extend_from_slice(&word(offset_a));
        out.extend_from_slice(&word(offset_b));
        out.extend_from_slice(&word(a.len()));
        out.extend_from_slice(a);
        out.extend_from_slice(&vec![0u8; a_padded - a.len()]);
        out.extend_from_slice(&word(b.len()));
        out.extend_from_slice(b);
        out.extend_from_slice(&vec![0u8; b_padded - b.len()]);
        out
    }

    fn build_shield_calldata(bundle: &tiny_privacy_vm_confidential_backend::PublicBalanceChangeBundle) -> Vec<u8> {
        let tx_bytes = serialize_public_balance_change_tx_bytes(&bundle.public);
        let artifacts = encode_tinyvm_artifacts(&serialize_public_balance_change_artifacts(&bundle.proof));
        let mut cd = Vec::from(SHIELD_PUBLIC_SELECTOR);
        cd.extend(abi_encode_two_bytes(&tx_bytes, &artifacts));
        cd
    }

    fn build_transfer_calldata(tc: &tiny_privacy_vm_confidential_backend::TransferCall) -> Vec<u8> {
        let tx_bytes = serialize_transfer_tx_bytes(&tc.bundle.public);
        let artifacts = encode_tinyvm_artifacts(&serialize_transfer_artifacts(&tc.bundle.proof, &tc.sidecars));
        let mut cd = Vec::from(TRANSFER_CONFIDENTIAL_SELECTOR);
        cd.extend(abi_encode_two_bytes(&tx_bytes, &artifacts));
        cd
    }

    fn build_unshield_calldata(bundle: &tiny_privacy_vm_confidential_backend::PublicBalanceChangeBundle) -> Vec<u8> {
        let tx_bytes = serialize_public_balance_change_tx_bytes(&bundle.public);
        let artifacts = encode_tinyvm_artifacts(&serialize_public_balance_change_artifacts(&bundle.proof));
        let mut cd = Vec::from(UNSHIELD_PUBLIC_SELECTOR);
        cd.extend(abi_encode_two_bytes(&tx_bytes, &artifacts));
        cd
    }

    fn build_register_calldata(token: [u8; 32], public_asset: [u8; 20]) -> Vec<u8> {
        let mut cd = Vec::from(REGISTER_TOKEN_SELECTOR);
        cd.extend_from_slice(&token);
        cd.extend_from_slice(&[0u8; 12]); // left-pad address to 32 bytes
        cd.extend_from_slice(&public_asset);
        cd
    }

    // Simulate the C++ store bridge — a BTreeMap that stores values correctly
    static TEST_STORE: Mutex<Option<BTreeMap<Vec<u8>, Vec<u8>>>> = Mutex::new(None);

    unsafe extern "C" fn test_store_get(
        _ctx: *mut c_void,
        key: *const u8, key_len: usize,
        value_buf: *mut u8, value_buf_len: usize,
        value_len: *mut usize,
    ) -> i32 {
        let key_slice = unsafe { slice::from_raw_parts(key, key_len) };
        let store = TEST_STORE.lock().unwrap();
        match store.as_ref().unwrap().get(key_slice) {
            Some(val) => {
                let copy_len = val.len().min(value_buf_len);
                unsafe {
                    std::ptr::copy_nonoverlapping(val.as_ptr(), value_buf, copy_len);
                    *value_len = copy_len;
                }
                1
            }
            None => {
                unsafe { *value_len = 0; }
                0
            }
        }
    }

    unsafe extern "C" fn test_store_set(
        _ctx: *mut c_void,
        key: *const u8, key_len: usize,
        value: *const u8, value_len: usize,
    ) {
        let key_slice = unsafe { slice::from_raw_parts(key, key_len) };
        let val_slice = unsafe { slice::from_raw_parts(value, value_len) };
        let mut store = TEST_STORE.lock().unwrap();
        store.as_mut().unwrap().insert(key_slice.to_vec(), val_slice.to_vec());
    }

    fn call_tinyvm_apply(sender: [u8; 20], value: u64, calldata: &[u8]) -> (bool, i64, String) {
        let mut result = TinyVmApplyResult {
            escrow_delta: 0,
            token: [0; 32],
            owner: [0; 20],
            success: 0,
        };
        let mut error_buf = vec![0u8; 256];

        let rc = unsafe {
            tinyvm_apply(
                sender.as_ptr(), sender.len(),
                value,
                calldata.as_ptr(), calldata.len(),
                std::ptr::null_mut(),
                test_store_get,
                test_store_set,
                &mut result,
                error_buf.as_mut_ptr(), error_buf.len(),
            )
        };

        let error_msg = if rc != 1 {
            let nul = error_buf.iter().position(|&b| b == 0).unwrap_or(error_buf.len());
            String::from_utf8_lossy(&error_buf[..nul]).to_string()
        } else {
            String::new()
        };

        (result.success == 1, result.escrow_delta, error_msg)
    }

    fn call_tinyvm_gas(calldata: &[u8]) -> u64 {
        unsafe { tinyvm_gas_cost(calldata.as_ptr(), calldata.len()) }
    }

    #[test]
    fn ffi_full_flow_via_abi_calldata() {
        // Initialize the test store
        *TEST_STORE.lock().unwrap() = Some(BTreeMap::new());

        let cfg = CryptoConfig::default();
        let token = [0x7au8; 32];
        let public_asset = native_mon_public_asset();
        let alice: [u8; 20] = [0xa1; 20];
        let bob: [u8; 20] = [0xb2; 20];

        // 1. registerToken
        let cd = build_register_calldata(token, public_asset);
        assert!(call_tinyvm_gas(&cd) > 0, "gas_cost should be >0 for registerToken");
        let (ok, _, err) = call_tinyvm_apply(alice, 0, &cd);
        assert!(ok, "registerToken failed: {err}");

        // 2. Shield Alice (90 wei)
        let alice_local = new_empty_local_account(&cfg, alice, token);
        let (shield_bundle, alice_after) = prove_shield_public(&cfg, &alice_local, 90).unwrap();
        let cd = build_shield_calldata(&shield_bundle);
        assert!(call_tinyvm_gas(&cd) > 0, "gas_cost should be >0 for shield");
        let (ok, _, err) = call_tinyvm_apply(alice, 90, &cd);
        assert!(ok, "shield alice failed: {err}");

        // 3. Shield Bob (7 wei)
        let bob_local = new_empty_local_account(&cfg, bob, token);
        let (shield_bundle, bob_after) = prove_shield_public(&cfg, &bob_local, 7).unwrap();
        let cd = build_shield_calldata(&shield_bundle);
        let (ok, _, err) = call_tinyvm_apply(bob, 7, &cd);
        assert!(ok, "shield bob failed: {err}");

        // 4. Transfer Alice -> Bob (30)
        let mut rng = rand::thread_rng();
        let (_, auditor_pub) = generate_auditor_keypair(&mut rng);
        let (transfer_call, _alice_after2) = prove_transfer_with_sidecars(
            &cfg, &alice_after, &bob_after, 30, Some(auditor_pub), &mut rng,
        ).unwrap();
        let cd = build_transfer_calldata(&transfer_call);
        assert!(call_tinyvm_gas(&cd) > 0, "gas_cost should be >0 for transfer");
        let (ok, _, err) = call_tinyvm_apply(alice, 0, &cd);
        assert!(ok, "transfer failed: {err}");

        // 5. Unshield Bob (5 wei)
        let bob_after_transfer = apply_encrypted_recipient_memo(
            &cfg, &bob_after,
            &AccountState {
                owner: bob, token, version: 2,
                commitment: transfer_call.bundle.public.recipient_new_commitment,
            },
            transfer_call.sidecars.recipient_encrypted_memo.as_ref().unwrap(),
        ).unwrap();
        let (unshield_bundle, _) = prove_unshield_public(&cfg, &bob_after_transfer, 5).unwrap();
        let cd = build_unshield_calldata(&unshield_bundle);
        let (ok, _, err) = call_tinyvm_apply(bob, 0, &cd);
        assert!(ok, "unshield failed: {err}");

        // Cleanup
        *TEST_STORE.lock().unwrap() = None;
    }

    #[test]
    fn ffi_normalize_abi_shield_round_trips() {
        let cfg = CryptoConfig::default();
        let alice: [u8; 20] = [0xa1; 20];
        let token = [0x7au8; 32];
        let local = new_empty_local_account(&cfg, alice, token);
        let (bundle, _) = prove_shield_public(&cfg, &local, 50).unwrap();
        let cd = build_shield_calldata(&bundle);

        // Verify ABI calldata normalizes to valid TVM2 envelope
        let normalized = normalize_input(&cd).expect("normalize should succeed");
        assert!(normalized.starts_with(&TINYVM_CALL_MAGIC), "normalized must have TVM2 magic");

        let decoded = tiny_privacy_vm_runtime::decode_tinyvm_call(&normalized).unwrap();
        assert_eq!(decoded.backend_id, CONFIDENTIAL_BACKEND_ID);
        assert_eq!(decoded.operation, TinyVmOperation::Shield);
    }
}
