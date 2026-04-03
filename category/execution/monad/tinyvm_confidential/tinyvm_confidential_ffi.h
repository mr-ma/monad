// Copyright (C) 2026 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct tinyvm_backend_transfer_public_out
{
    uint8_t token[32];
    uint8_t from[20];
    uint8_t to[20];
    uint64_t sender_version;
    uint64_t recipient_version;
    uint8_t sender_old_commitment[32];
    uint8_t sender_new_commitment[32];
    uint8_t recipient_old_commitment[32];
    uint8_t recipient_new_commitment[32];
} tinyvm_backend_transfer_public_out;

typedef struct tinyvm_backend_public_balance_change_public_out
{
    uint8_t kind;
    uint8_t token[32];
    uint8_t owner[20];
    uint64_t version;
    uint64_t public_amount;
    uint8_t old_commitment[32];
    uint8_t new_commitment[32];
} tinyvm_backend_public_balance_change_public_out;

int tinyvm_verify_transfer_backend_call(
    uint32_t backend_id, uint8_t const *tx_bytes_ptr, size_t tx_bytes_len,
    uint8_t const *artifacts_ptr, size_t artifacts_len,
    tinyvm_backend_transfer_public_out *out_public, char *error_buf,
    size_t error_len);

int tinyvm_verify_public_balance_change_backend_call(
    uint32_t backend_id, uint8_t const *tx_bytes_ptr, size_t tx_bytes_len,
    uint8_t const *artifacts_ptr, size_t artifacts_len,
    tinyvm_backend_public_balance_change_public_out *out_public, char *error_buf,
    size_t error_len);

int tinyvm_backend_empty_commitment(uint32_t backend_id, uint8_t *out_commitment);

#ifdef __cplusplus
}
#endif
