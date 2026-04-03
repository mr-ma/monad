// Copyright (C) 2026 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#pragma once

#include <category/core/byte_string.hpp>
#include <category/core/config.hpp>
#include <category/core/int.hpp>
#include <category/core/result.hpp>
#include <category/execution/ethereum/core/address.hpp>
#include <category/execution/ethereum/core/contract/big_endian.hpp>
#include <category/execution/ethereum/state3/state.hpp>
#include <category/execution/ethereum/trace/call_tracer.hpp>
#include <category/vm/evm/traits.hpp>

MONAD_NAMESPACE_BEGIN

inline constexpr Address TINYVM_CONFIDENTIAL_CA = Address{0x420};

// TODO: Use MIP-8 page-based optimisation for storage layout
struct TinyVmConfidentialTokenStorage
{
    u64_be asset_kind;
    Address public_asset;
    u64_be escrowed_public_amount;
};

struct TinyVmConfidentialAccountStorage
{
    u64_be version;
    bytes32_t commitment;
};

static_assert(std::has_unique_object_representations_v<TinyVmConfidentialTokenStorage>);
static_assert(std::has_unique_object_representations_v<TinyVmConfidentialAccountStorage>);

class TinyVmConfidentialContract
{
    State &state_;
    [[maybe_unused]] CallTracerBase &call_tracer_;

public:
    using TokenStorage = TinyVmConfidentialTokenStorage;
    using AccountStorage = TinyVmConfidentialAccountStorage;

    TinyVmConfidentialContract(State &state, CallTracerBase &tracer);

    using PrecompileFunc = Result<byte_string> (TinyVmConfidentialContract::*)(
        byte_string_view, evmc_address const &, evmc_bytes32 const &);

    template <Traits traits>
    static std::pair<PrecompileFunc, uint64_t>
    precompile_dispatch(byte_string_view &);

    Result<byte_string> precompile_register_token(
        byte_string_view, evmc_address const &, evmc_uint256be const &);
    Result<byte_string> precompile_shield_public(
        byte_string_view, evmc_address const &, evmc_uint256be const &);
    Result<byte_string> precompile_transfer_confidential(
        byte_string_view, evmc_address const &, evmc_uint256be const &);
    Result<byte_string> precompile_unshield_public(
        byte_string_view, evmc_address const &, evmc_uint256be const &);
    Result<byte_string> precompile_fallback(
        byte_string_view, evmc_address const &, evmc_uint256be const &);

    static bytes32_t token_storage_key(bytes32_t const &token);
    static bytes32_t account_storage_key(
        bytes32_t const &token, Address const &owner);
};

MONAD_NAMESPACE_END
