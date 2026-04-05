// Copyright (C) 2026 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#include <category/core/keccak.hpp>
#include <category/execution/ethereum/core/contract/abi_decode.hpp>
#include <category/execution/ethereum/core/contract/abi_encode.hpp>
#include <category/execution/ethereum/core/contract/abi_signatures.hpp>
#include <category/execution/ethereum/core/contract/storage_variable.hpp>
#include <category/execution/monad/tinyvm_confidential/tinyvm_confidential_contract.hpp>
#include <category/execution/monad/tinyvm_confidential/tinyvm_confidential_error.hpp>
#include <category/execution/monad/tinyvm_confidential/tinyvm_confidential_ffi.h>
#include <category/vm/evm/explicit_traits.hpp>

#include <boost/outcome/success_failure.hpp>
#include <boost/outcome/try.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

MONAD_ANONYMOUS_NAMESPACE_BEGIN

struct PrecompileSelector
{
    static constexpr uint32_t REGISTER_TOKEN =
        abi_encode_selector("registerToken(bytes32,address)");
    static constexpr uint32_t SHIELD_PUBLIC =
        abi_encode_selector("shieldPublic(bytes,bytes)");
    static constexpr uint32_t TRANSFER_CONFIDENTIAL =
        abi_encode_selector("transferConfidential(bytes,bytes)");
    static constexpr uint32_t UNSHIELD_PUBLIC =
        abi_encode_selector("unshieldPublic(bytes,bytes)");
};

constexpr uint64_t REGISTER_TOKEN_COST = 500;
constexpr uint64_t SHIELD_PUBLIC_COST = 60'000;
constexpr uint64_t TRANSFER_CONFIDENTIAL_COST = 80'000;
constexpr uint64_t UNSHIELD_PUBLIC_COST = 60'000;
constexpr uint64_t FALLBACK_COST = 100;

constexpr unsigned char TOKEN_NAMESPACE[] = "tinyvm/confidential/token/v1";
constexpr unsigned char ACCOUNT_NAMESPACE[] = "tinyvm/confidential/account/v1";
constexpr size_t ERROR_BUF_LEN = 256;
constexpr Address NATIVE_MON_ASSET = Address{};
constexpr uint64_t ASSET_KIND_NATIVE_MON = 1;
constexpr uint64_t ASSET_KIND_MRC20 = 2;
constexpr uint32_t CONFIDENTIAL_BACKEND_ID = 1;

Result<void> function_not_payable(evmc_uint256be const &value)
{
    bool const all_zero = std::all_of(
        value.bytes,
        value.bytes + sizeof(evmc_uint256be),
        [](uint8_t const byte) { return byte == 0; });

    if (MONAD_UNLIKELY(!all_zero)) {
        return TinyVmConfidentialError::ValueNonZero;
    }
    return outcome::success();
}

bool is_native_asset(Address const &public_asset)
{
    return public_asset == NATIVE_MON_ASSET;
}

uint64_t asset_kind_for(Address const &public_asset)
{
    return is_native_asset(public_asset) ? ASSET_KIND_NATIVE_MON : ASSET_KIND_MRC20;
}

Result<uint64_t> checked_add_amount(uint64_t lhs, uint64_t rhs)
{
    if (MONAD_UNLIKELY(lhs > std::numeric_limits<uint64_t>::max() - rhs)) {
        return TinyVmConfidentialError::InvalidInput;
    }
    return lhs + rhs;
}

Result<uint64_t> decode_u64_value(evmc_uint256be const &value)
{
    auto const native = intx::be::load<uint256_t>(value);
    if (MONAD_UNLIKELY(native > std::numeric_limits<uint64_t>::max())) {
        return TinyVmConfidentialError::InvalidInput;
    }
    return static_cast<uint64_t>(native);
}

Result<bytes32_t> decode_bytes32_fixed(byte_string_view &enc)
{
    if (MONAD_UNLIKELY(enc.size() < 32)) {
        return TinyVmConfidentialError::InvalidInput;
    }

    bytes32_t output{};
    std::memcpy(output.bytes, enc.data(), sizeof(output.bytes));
    enc.remove_prefix(32);
    return output;
}

Result<size_t> decode_offset_or_length(u256_be const &value)
{
    auto const native = value.native();
    if (MONAD_UNLIKELY(native > std::numeric_limits<size_t>::max())) {
        return TinyVmConfidentialError::InvalidInput;
    }
    return static_cast<size_t>(native);
}

Result<byte_string> decode_dynamic_bytes_tail(byte_string_view &tail)
{
    if (MONAD_UNLIKELY(tail.size() < 32)) {
        return TinyVmConfidentialError::InvalidInput;
    }
    BOOST_OUTCOME_TRY(auto const len_be, abi_decode_fixed<u256_be>(tail));
    BOOST_OUTCOME_TRY(auto const len, decode_offset_or_length(len_be));

    size_t const padded = ((len + 31) / 32) * 32;
    if (MONAD_UNLIKELY(tail.size() < padded)) {
        return TinyVmConfidentialError::InvalidInput;
    }

    byte_string output;
    output.insert(output.end(), tail.begin(), tail.begin() + len);
    tail.remove_prefix(padded);
    return output;
}

struct DetachedBackendCallInput
{
    byte_string tx_bytes;
    byte_string artifacts;
};

Result<DetachedBackendCallInput> decode_detached_backend_call_input(
    byte_string_view const &input)
{
    auto head = input;
    BOOST_OUTCOME_TRY(auto const tx_offset_be, abi_decode_fixed<u256_be>(head));
    BOOST_OUTCOME_TRY(auto const artifacts_offset_be, abi_decode_fixed<u256_be>(head));
    BOOST_OUTCOME_TRY(auto const tx_offset, decode_offset_or_length(tx_offset_be));
    BOOST_OUTCOME_TRY(
        auto const artifacts_offset, decode_offset_or_length(artifacts_offset_be));

    if (MONAD_UNLIKELY(tx_offset != 64 || artifacts_offset < tx_offset)) {
        return TinyVmConfidentialError::InvalidInput;
    }

    auto tail = input.substr(tx_offset);
    BOOST_OUTCOME_TRY(auto const tx_bytes, decode_dynamic_bytes_tail(tail));
    BOOST_OUTCOME_TRY(auto const artifacts, decode_dynamic_bytes_tail(tail));

    return DetachedBackendCallInput{
        .tx_bytes = std::move(tx_bytes),
        .artifacts = std::move(artifacts),
    };
}

bytes32_t keccak_key(
    byte_string_view const &prefix, bytes32_t const &token,
    std::optional<Address> const &owner = std::nullopt)
{
    byte_string input;
    input.insert(input.end(), prefix.begin(), prefix.end());
    input.insert(input.end(), token.bytes, token.bytes + sizeof(token.bytes));
    if (owner.has_value()) {
        input.insert(
            input.end(),
            owner->bytes,
            owner->bytes + sizeof(owner->bytes));
    }
    return to_bytes(keccak256(byte_string_view{input.data(), input.size()}));
}

std::array<unsigned char, 32> empty_commitment_bytes()
{
    std::array<unsigned char, 32> out{};
    auto const ok = tinyvm_backend_empty_commitment(CONFIDENTIAL_BACKEND_ID, out.data());
    MONAD_ASSERT(ok == 1);
    return out;
}

Result<void> ffi_verify_transfer(
    DetachedBackendCallInput const &call, tinyvm_backend_transfer_public_out &out)
{
    std::array<char, ERROR_BUF_LEN> error_buf{};
    auto const ok = tinyvm_verify_transfer_backend_call(
        CONFIDENTIAL_BACKEND_ID,
        call.tx_bytes.data(),
        call.tx_bytes.size(),
        call.artifacts.data(),
        call.artifacts.size(),
        &out,
        error_buf.data(),
        error_buf.size());
    if (ok != 1) {
        return TinyVmConfidentialError::VerificationFailed;
    }
    return outcome::success();
}

Result<void> ffi_verify_public_balance_change(
    DetachedBackendCallInput const &call,
    tinyvm_backend_public_balance_change_public_out &out)
{
    std::array<char, ERROR_BUF_LEN> error_buf{};
    auto const ok = tinyvm_verify_public_balance_change_backend_call(
        CONFIDENTIAL_BACKEND_ID,
        call.tx_bytes.data(),
        call.tx_bytes.size(),
        call.artifacts.data(),
        call.artifacts.size(),
        &out,
        error_buf.data(),
        error_buf.size());
    if (ok != 1) {
        return TinyVmConfidentialError::VerificationFailed;
    }
    return outcome::success();
}

bytes32_t as_bytes32(unsigned char const (&bytes)[32])
{
    bytes32_t out{};
    std::memcpy(out.bytes, bytes, sizeof(out.bytes));
    return out;
}

bytes32_t as_bytes32(std::array<unsigned char, 32> const &bytes)
{
    bytes32_t out{};
    std::memcpy(out.bytes, bytes.data(), sizeof(out.bytes));
    return out;
}

Address as_address(unsigned char const (&bytes)[20])
{
    Address out{};
    std::memcpy(out.bytes, bytes, sizeof(out.bytes));
    return out;
}

MONAD_ANONYMOUS_NAMESPACE_END

MONAD_NAMESPACE_BEGIN

TinyVmConfidentialContract::TinyVmConfidentialContract(
    State &state, CallTracerBase &tracer)
    : state_{state}
    , call_tracer_{tracer}
{
    state_.add_to_balance(TINYVM_CONFIDENTIAL_CA, 0);
}

template <Traits traits>
std::pair<TinyVmConfidentialContract::PrecompileFunc, uint64_t>
TinyVmConfidentialContract::precompile_dispatch(byte_string_view &input)
{
    if (MONAD_UNLIKELY(input.size() < 4)) {
        return {&TinyVmConfidentialContract::precompile_fallback, FALLBACK_COST};
    }

    auto const signature =
        intx::be::unsafe::load<uint32_t>(input.substr(0, 4).data());
    input.remove_prefix(4);

    switch (signature) {
    case PrecompileSelector::REGISTER_TOKEN:
        return {
            &TinyVmConfidentialContract::precompile_register_token,
            REGISTER_TOKEN_COST};
    case PrecompileSelector::SHIELD_PUBLIC:
        return {
            &TinyVmConfidentialContract::precompile_shield_public,
            SHIELD_PUBLIC_COST};
    case PrecompileSelector::TRANSFER_CONFIDENTIAL:
        return {
            &TinyVmConfidentialContract::precompile_transfer_confidential,
            TRANSFER_CONFIDENTIAL_COST};
    case PrecompileSelector::UNSHIELD_PUBLIC:
        return {
            &TinyVmConfidentialContract::precompile_unshield_public,
            UNSHIELD_PUBLIC_COST};
    default:
        return {&TinyVmConfidentialContract::precompile_fallback, FALLBACK_COST};
    }
}

EXPLICIT_MONAD_TRAITS(TinyVmConfidentialContract::precompile_dispatch);

bytes32_t TinyVmConfidentialContract::token_storage_key(bytes32_t const &token)
{
    return keccak_key(to_byte_string_view(TOKEN_NAMESPACE), token);
}

bytes32_t TinyVmConfidentialContract::account_storage_key(
    bytes32_t const &token, Address const &owner)
{
    return keccak_key(to_byte_string_view(ACCOUNT_NAMESPACE), token, owner);
}

Result<byte_string> TinyVmConfidentialContract::precompile_register_token(
    byte_string_view input, evmc_address const &msg_sender,
    evmc_uint256be const &msg_value)
{
    BOOST_OUTCOME_TRY(function_not_payable(msg_value));
    (void)msg_sender;

    BOOST_OUTCOME_TRY(auto const token, decode_bytes32_fixed(input));
    BOOST_OUTCOME_TRY(auto const public_asset, abi_decode_fixed<Address>(input));
    if (MONAD_UNLIKELY(!input.empty())) {
        return TinyVmConfidentialError::InvalidInput;
    }

    StorageVariable<TokenStorage> token_var{
        state_, TINYVM_CONFIDENTIAL_CA, token_storage_key(token)};
    if (auto const current = token_var.load_checked()) {
        if (current->public_asset == public_asset) {
            return byte_string{abi_encode_bool(true)};
        }
        return TinyVmConfidentialError::TokenAlreadyRegistered;
    }

    token_var.store(TokenStorage{
        .asset_kind = u64_be{asset_kind_for(public_asset)},
        .public_asset = public_asset,
        .escrowed_public_amount = u64_be{0},
    });
    return byte_string{abi_encode_bool(true)};
}

Result<byte_string> TinyVmConfidentialContract::precompile_shield_public(
    byte_string_view input, evmc_address const &msg_sender,
    evmc_uint256be const &msg_value)
{
    BOOST_OUTCOME_TRY(auto const detached_call, decode_detached_backend_call_input(input));

    tinyvm_backend_public_balance_change_public_out verified{};
    BOOST_OUTCOME_TRY(ffi_verify_public_balance_change(detached_call, verified));
    if (MONAD_UNLIKELY(verified.kind != 0)) {
        return TinyVmConfidentialError::InvalidKind;
    }

    auto const token = as_bytes32(verified.token);
    StorageVariable<TokenStorage> token_var{
        state_, TINYVM_CONFIDENTIAL_CA, token_storage_key(token)};
    auto const token_cfg = token_var.load_checked();
    if (!token_cfg.has_value()) {
        return TinyVmConfidentialError::TokenNotRegistered;
    }
    auto const owner = as_address(verified.owner);
    if (MONAD_UNLIKELY(msg_sender != owner)) {
        return TinyVmConfidentialError::SenderMismatch;
    }

    BOOST_OUTCOME_TRY(auto const msg_value_u64, decode_u64_value(msg_value));
    if (is_native_asset(token_cfg->public_asset)) {
        if (MONAD_UNLIKELY(msg_value_u64 != verified.public_amount)) {
            return TinyVmConfidentialError::ValueNonZero;
        }
    }
    else {
        BOOST_OUTCOME_TRY(function_not_payable(msg_value));
    }

    StorageVariable<AccountStorage> account_var{
        state_, TINYVM_CONFIDENTIAL_CA, account_storage_key(token, owner)};
    auto const current = account_var.load_checked();

    if (!current.has_value()) {
        if (MONAD_UNLIKELY(verified.version != 0)) {
            return TinyVmConfidentialError::VersionMismatch;
        }
        if (MONAD_UNLIKELY(
                as_bytes32(verified.old_commitment) !=
                as_bytes32(empty_commitment_bytes()))) {
            return TinyVmConfidentialError::CommitmentMismatch;
        }

        account_var.store(AccountStorage{
            .version = u64_be{1},
            .commitment = as_bytes32(verified.new_commitment),
        });
        BOOST_OUTCOME_TRY(auto const next_escrow, checked_add_amount(
                                                     token_cfg->escrowed_public_amount.native(),
                                                     verified.public_amount));
        token_var.store(TokenStorage{
            .asset_kind = token_cfg->asset_kind,
            .public_asset = token_cfg->public_asset,
            .escrowed_public_amount = u64_be{next_escrow},
        });
        return byte_string{abi_encode_bool(true)};
    }

    if (MONAD_UNLIKELY(current->version.native() != verified.version)) {
        return TinyVmConfidentialError::VersionMismatch;
    }
    if (MONAD_UNLIKELY(
            current->commitment != as_bytes32(verified.old_commitment))) {
        return TinyVmConfidentialError::CommitmentMismatch;
    }

    account_var.store(AccountStorage{
        .version = u64_be{verified.version + 1},
        .commitment = as_bytes32(verified.new_commitment),
    });
    BOOST_OUTCOME_TRY(auto const next_escrow, checked_add_amount(
                                                 token_cfg->escrowed_public_amount.native(),
                                                 verified.public_amount));
    token_var.store(TokenStorage{
        .asset_kind = token_cfg->asset_kind,
        .public_asset = token_cfg->public_asset,
        .escrowed_public_amount = u64_be{next_escrow},
    });
    return byte_string{abi_encode_bool(true)};
}

Result<byte_string> TinyVmConfidentialContract::precompile_transfer_confidential(
    byte_string_view input, evmc_address const &msg_sender,
    evmc_uint256be const &msg_value)
{
    BOOST_OUTCOME_TRY(function_not_payable(msg_value));
    BOOST_OUTCOME_TRY(auto const detached_call, decode_detached_backend_call_input(input));

    tinyvm_backend_transfer_public_out verified{};
    BOOST_OUTCOME_TRY(ffi_verify_transfer(detached_call, verified));

    auto const token = as_bytes32(verified.token);
    StorageVariable<TokenStorage> token_var{
        state_, TINYVM_CONFIDENTIAL_CA, token_storage_key(token)};
    if (!token_var.load_checked().has_value()) {
        return TinyVmConfidentialError::TokenNotRegistered;
    }

    auto const from = as_address(verified.from);
    auto const to = as_address(verified.to);
    // Sender check removed: Sigma proof of Pedersen opening authorizes the transfer.
    // This enables smart contract composability (compliance vaults, batchers).
    (void)msg_sender;

    StorageVariable<AccountStorage> sender_var{
        state_, TINYVM_CONFIDENTIAL_CA, account_storage_key(token, from)};
    StorageVariable<AccountStorage> recipient_var{
        state_, TINYVM_CONFIDENTIAL_CA, account_storage_key(token, to)};

    auto const sender_state = sender_var.load_checked();
    auto const recipient_state = recipient_var.load_checked();
    if (!sender_state.has_value() || !recipient_state.has_value()) {
        return TinyVmConfidentialError::MissingAccount;
    }

    if (MONAD_UNLIKELY(sender_state->version.native() != verified.sender_version) ||
        MONAD_UNLIKELY(recipient_state->version.native() != verified.recipient_version)) {
        return TinyVmConfidentialError::VersionMismatch;
    }
    if (MONAD_UNLIKELY(
            sender_state->commitment != as_bytes32(verified.sender_old_commitment)) ||
        MONAD_UNLIKELY(
            recipient_state->commitment !=
            as_bytes32(verified.recipient_old_commitment))) {
        return TinyVmConfidentialError::CommitmentMismatch;
    }

    sender_var.store(AccountStorage{
        .version = u64_be{verified.sender_version + 1},
        .commitment = as_bytes32(verified.sender_new_commitment),
    });
    recipient_var.store(AccountStorage{
        .version = u64_be{verified.recipient_version + 1},
        .commitment = as_bytes32(verified.recipient_new_commitment),
    });
    return byte_string{abi_encode_bool(true)};
}

Result<byte_string> TinyVmConfidentialContract::precompile_unshield_public(
    byte_string_view input, evmc_address const &msg_sender,
    evmc_uint256be const &msg_value)
{
    BOOST_OUTCOME_TRY(function_not_payable(msg_value));
    BOOST_OUTCOME_TRY(auto const detached_call, decode_detached_backend_call_input(input));

    tinyvm_backend_public_balance_change_public_out verified{};
    BOOST_OUTCOME_TRY(ffi_verify_public_balance_change(detached_call, verified));
    if (MONAD_UNLIKELY(verified.kind != 1)) {
        return TinyVmConfidentialError::InvalidKind;
    }

    auto const token = as_bytes32(verified.token);
    StorageVariable<TokenStorage> token_var{
        state_, TINYVM_CONFIDENTIAL_CA, token_storage_key(token)};
    auto const token_cfg = token_var.load_checked();
    if (!token_cfg.has_value()) {
        return TinyVmConfidentialError::TokenNotRegistered;
    }

    auto const owner = as_address(verified.owner);
    if (MONAD_UNLIKELY(msg_sender != owner)) {
        return TinyVmConfidentialError::SenderMismatch;
    }
    StorageVariable<AccountStorage> account_var{
        state_, TINYVM_CONFIDENTIAL_CA, account_storage_key(token, owner)};
    auto const current = account_var.load_checked();
    if (!current.has_value()) {
        return TinyVmConfidentialError::MissingAccount;
    }
    if (MONAD_UNLIKELY(current->version.native() != verified.version)) {
        return TinyVmConfidentialError::VersionMismatch;
    }
    if (MONAD_UNLIKELY(
            current->commitment != as_bytes32(verified.old_commitment))) {
        return TinyVmConfidentialError::CommitmentMismatch;
    }
    if (MONAD_UNLIKELY(
            token_cfg->escrowed_public_amount.native() < verified.public_amount)) {
        return TinyVmConfidentialError::InsufficientEscrow;
    }

    account_var.store(AccountStorage{
        .version = u64_be{verified.version + 1},
        .commitment = as_bytes32(verified.new_commitment),
    });
    token_var.store(TokenStorage{
        .asset_kind = token_cfg->asset_kind,
        .public_asset = token_cfg->public_asset,
        .escrowed_public_amount =
            u64_be{token_cfg->escrowed_public_amount.native() - verified.public_amount},
    });
    if (is_native_asset(token_cfg->public_asset)) {
        state_.add_to_balance(owner, verified.public_amount);
        state_.subtract_from_balance(TINYVM_CONFIDENTIAL_CA, verified.public_amount);
    }
    return byte_string{abi_encode_bool(true)};
}

Result<byte_string> TinyVmConfidentialContract::precompile_fallback(
    byte_string_view, evmc_address const &, evmc_uint256be const &)
{
    return TinyVmConfidentialError::MethodNotSupported;
}

MONAD_NAMESPACE_END
