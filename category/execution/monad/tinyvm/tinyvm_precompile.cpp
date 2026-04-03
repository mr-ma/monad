// Copyright (C) 2026 Category Labs, Inc.
//
// Generic TinyVM precompile. Delegates all logic to Rust via FFI.

#include <category/execution/monad/tinyvm/tinyvm_precompile.hpp>
#include <category/execution/monad/tinyvm/tinyvm_ffi.h>
#include <category/execution/ethereum/core/contract/abi_encode.hpp>
#include <category/vm/evm/explicit_traits.hpp>

#include <boost/outcome/try.hpp>
#include <array>
#include <cstring>
#include <limits>

MONAD_ANONYMOUS_NAMESPACE_BEGIN

constexpr uint64_t TINYVM_FALLBACK_COST = 100;
constexpr size_t ERROR_BUF_LEN = 256;

// Bridge C++ State to Rust TinyVmStateStore via FFI callbacks.
struct StoreContext
{
    monad::State *state;
    monad::Address const *precompile_addr;
};

int store_get_callback(
    void *ctx,
    uint8_t const *key, size_t key_len,
    uint8_t *value_buf, size_t value_buf_len,
    size_t *value_len)
{
    auto *sc = static_cast<StoreContext *>(ctx);
    // Map Rust store key to EVM storage slot via keccak
    // For now, use the key bytes directly as the storage slot
    // (padded to bytes32 or hashed if > 32 bytes)
    monad::bytes32_t slot{};
    if (key_len <= 32) {
        std::memcpy(slot.bytes + 32 - key_len, key, key_len);
    } else {
        // Hash long keys
        auto hash = monad::keccak256(monad::byte_string_view{key, key_len});
        std::memcpy(slot.bytes, hash.bytes, 32);
    }

    auto const val = sc->state->get_storage(*sc->precompile_addr, slot);
    std::memcpy(value_buf, val.bytes, std::min(value_buf_len, sizeof(val.bytes)));
    *value_len = sizeof(val.bytes);
    return 1;
}

void store_set_callback(
    void *ctx,
    uint8_t const *key, size_t key_len,
    uint8_t const *value, size_t value_len)
{
    auto *sc = static_cast<StoreContext *>(ctx);
    monad::bytes32_t slot{};
    if (key_len <= 32) {
        std::memcpy(slot.bytes + 32 - key_len, key, key_len);
    } else {
        auto hash = monad::keccak256(monad::byte_string_view{key, key_len});
        std::memcpy(slot.bytes, hash.bytes, 32);
    }

    monad::bytes32_t val{};
    std::memcpy(val.bytes, value, std::min(value_len, sizeof(val.bytes)));
    sc->state->set_storage(*sc->precompile_addr, slot, val);
}

MONAD_ANONYMOUS_NAMESPACE_END

MONAD_NAMESPACE_BEGIN

TinyVmPrecompile::TinyVmPrecompile(State &state, CallTracerBase &tracer)
    : state_{state}
    , call_tracer_{tracer}
{
    state_.add_to_balance(TINYVM_PRECOMPILE_ADDRESS, 0);
}

template <Traits traits>
std::pair<TinyVmPrecompile::PrecompileFunc, uint64_t>
TinyVmPrecompile::precompile_dispatch(byte_string_view &input)
{
    uint64_t cost = tinyvm_gas_cost(input.data(), input.size());
    if (cost == 0) {
        return {&TinyVmPrecompile::precompile_fallback, TINYVM_FALLBACK_COST};
    }
    return {&TinyVmPrecompile::execute, cost};
}

EXPLICIT_MONAD_TRAITS(TinyVmPrecompile::precompile_dispatch);

Result<byte_string> TinyVmPrecompile::execute(
    byte_string_view input, evmc_address const &msg_sender,
    evmc_uint256be const &msg_value)
{
    // Decode tx.value as u64
    auto const native = intx::be::load<uint256_t>(msg_value);
    if (MONAD_UNLIKELY(native > std::numeric_limits<uint64_t>::max())) {
        return TinyVmPrecompileError::InvalidInput;
    }
    uint64_t const value_u64 = static_cast<uint64_t>(native);

    // Set up store callbacks bridging Rust → C++ State
    StoreContext store_ctx{&state_, &TINYVM_PRECOMPILE_ADDRESS};
    tinyvm_apply_result result{};
    std::array<char, ERROR_BUF_LEN> error_buf{};

    auto const rc = tinyvm_apply(
        msg_sender.bytes, sizeof(msg_sender.bytes),
        value_u64,
        input.data(), input.size(),
        &store_ctx,
        store_get_callback,
        store_set_callback,
        &result,
        error_buf.data(), error_buf.size());

    if (rc != 1 || !result.success) {
        return TinyVmPrecompileError::VerificationFailed;
    }

    // Apply escrow balance changes
    if (result.escrow_delta > 0) {
        // Shield: MON flows into precompile (already transferred via msg.value)
        // Nothing extra needed — msg.value already credited by EVM CALL handler
    } else if (result.escrow_delta < 0) {
        // Unshield: transfer MON from precompile to owner
        uint64_t amount = static_cast<uint64_t>(-result.escrow_delta);
        Address owner{};
        std::memcpy(owner.bytes, result.owner, sizeof(owner.bytes));
        state_.add_to_balance(owner, amount);
        state_.subtract_from_balance(TINYVM_PRECOMPILE_ADDRESS, amount);
    }

    return byte_string{abi_encode_bool(true)};
}

Result<byte_string> TinyVmPrecompile::precompile_fallback(
    byte_string_view, evmc_address const &, evmc_uint256be const &)
{
    return TinyVmPrecompileError::MethodNotSupported;
}

MONAD_NAMESPACE_END
