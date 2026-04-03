// Copyright (C) 2026 Category Labs, Inc.
//
// TinyVM generic FFI — single entry point for all backends.
// Rust owns verification + state logic; C++ provides State via callbacks.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

// Callbacks from Rust into C++ EVM State.
typedef int (*tinyvm_store_get_fn)(
    void *ctx,
    uint8_t const *key, size_t key_len,
    uint8_t *value_buf, size_t value_buf_len,
    size_t *value_len);

typedef void (*tinyvm_store_set_fn)(
    void *ctx,
    uint8_t const *key, size_t key_len,
    uint8_t const *value, size_t value_len);

typedef struct tinyvm_apply_result
{
    int64_t escrow_delta;    // +N = shield into precompile, -N = unshield out
    uint8_t token[32];       // token involved
    uint8_t owner[20];       // owner for unshield MON transfer
    uint8_t success;         // 1 = ok, 0 = revert
} tinyvm_apply_result;

// Generic TinyVM entry point.
// Decodes envelope, dispatches to backend, verifies proofs,
// reads/writes state via callbacks, returns escrow delta.
int tinyvm_apply(
    uint8_t const *sender, size_t sender_len,
    uint64_t tx_value,
    uint8_t const *input, size_t input_len,
    void *store_ctx,
    tinyvm_store_get_fn store_get,
    tinyvm_store_set_fn store_set,
    tinyvm_apply_result *result,
    char *error_buf, size_t error_len);

#ifdef __cplusplus
}
#endif
