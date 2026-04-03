// Copyright (C) 2026 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#include <category/execution/ethereum/core/contract/abi_encode.hpp>
#include <category/execution/ethereum/core/contract/abi_signatures.hpp>
#include <category/execution/ethereum/core/contract/storage_variable.hpp>
#include <category/execution/ethereum/db/trie_db.hpp>
#include <category/execution/ethereum/state2/block_state.hpp>
#include <category/execution/ethereum/state3/state.hpp>
#include <category/execution/ethereum/trace/call_tracer.hpp>
#include <category/execution/monad/tinyvm_confidential/tinyvm_confidential_contract.hpp>
#include <category/execution/monad/tinyvm_confidential/tinyvm_confidential_ffi.h>
#include <category/vm/vm.hpp>

#include <evmc/hex.hpp>
#include <intx/intx.hpp>
#include <nlohmann/json.hpp>

#include <gtest/gtest.h>

#include <boost/outcome/success_failure.hpp>

#include <fstream>
#include <filesystem>

using namespace monad;

 namespace
{

constexpr uint32_t CONFIDENTIAL_BACKEND_ID = 1;

struct TestSelector
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

struct DetachedBackendCallFixture
{
    byte_string tx_bytes;
    byte_string artifacts;
};

struct Fixture
{
    bytes32_t token{};
    Address public_asset{};
    Address alice{};
    Address bob{};
    DetachedBackendCallFixture shield_alice;
    DetachedBackendCallFixture shield_bob;
    DetachedBackendCallFixture transfer;
    DetachedBackendCallFixture unshield_bob;
};

bytes32_t hex_to_bytes32(std::string const &hex)
{
    auto const bytes = evmc::from_hex(hex).value();
    EXPECT_EQ(bytes.size(), 32);
    return [&]() {
        bytes32_t out{};
        std::memcpy(out.bytes, bytes.data(), 32);
        return out;
    }();
}

Address hex_to_address(std::string const &hex)
{
    auto const bytes = evmc::from_hex(hex).value();
    EXPECT_EQ(bytes.size(), 20);
    Address out{};
    std::memcpy(out.bytes, bytes.data(), 20);
    return out;
}

byte_string hex_to_bytes(std::string const &hex)
{
    return evmc::from_hex(hex).value();
}

DetachedBackendCallFixture load_detached_call(
    nlohmann::json const &json, std::string const &prefix)
{
    return DetachedBackendCallFixture{
        .tx_bytes = hex_to_bytes(json.at(prefix + "_tx_bytes").get<std::string>()),
        .artifacts = hex_to_bytes(json.at(prefix + "_artifacts").get<std::string>()),
    };
}

bytes32_t raw_to_bytes32(unsigned char const (&bytes)[32])
{
    bytes32_t out{};
    std::memcpy(out.bytes, bytes, 32);
    return out;
}

Fixture load_fixture()
{
    auto const path = std::filesystem::path{__FILE__}.parent_path() /
                      "tinyvm_confidential_fixture.json";
    std::ifstream input{path};
    EXPECT_TRUE(input.good()) << path;

    nlohmann::json json;
    input >> json;

    return Fixture{
        .token = hex_to_bytes32(json.at("token").get<std::string>()),
        .public_asset = hex_to_address(json.at("public_asset").get<std::string>()),
        .alice = hex_to_address(json.at("alice").get<std::string>()),
        .bob = hex_to_address(json.at("bob").get<std::string>()),
        .shield_alice = load_detached_call(json, "shield_alice"),
        .shield_bob = load_detached_call(json, "shield_bob"),
        .transfer = load_detached_call(json, "transfer"),
        .unshield_bob = load_detached_call(json, "unshield_bob"),
    };
}

byte_string prepend_selector(uint32_t selector, byte_string const &payload)
{
    u32_be selector_be{selector};
    byte_string out{selector_be.bytes, selector_be.bytes + sizeof(selector_be.bytes)};
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

byte_string make_register_call(bytes32_t const &token, Address const &public_asset)
{
    AbiEncoder encoder;
    u256_be token_be{};
    std::memcpy(token_be.bytes, token.bytes, sizeof(token.bytes));
    encoder.add_uint(token_be);
    encoder.add_address(public_asset);
    return prepend_selector(
        TestSelector::REGISTER_TOKEN,
        encoder.encode_final());
}

byte_string make_shield_call(
    byte_string const &tx_bytes, byte_string const &artifacts)
{
    AbiEncoder encoder;
    encoder.add_bytes(tx_bytes);
    encoder.add_bytes(artifacts);
    return prepend_selector(TestSelector::SHIELD_PUBLIC, encoder.encode_final());
}

byte_string make_transfer_call(
    byte_string const &tx_bytes, byte_string const &artifacts)
{
    AbiEncoder encoder;
    encoder.add_bytes(tx_bytes);
    encoder.add_bytes(artifacts);
    return prepend_selector(
        TestSelector::TRANSFER_CONFIDENTIAL,
        encoder.encode_final());
}

byte_string make_unshield_call(
    byte_string const &tx_bytes, byte_string const &artifacts)
{
    AbiEncoder encoder;
    encoder.add_bytes(tx_bytes);
    encoder.add_bytes(artifacts);
    return prepend_selector(
        TestSelector::UNSHIELD_PUBLIC,
        encoder.encode_final());
}

template <typename Out>
Out ffi_verify_bundle(
    DetachedBackendCallFixture const &bundle,
    int (*verify_fn)(
        uint32_t,
        uint8_t const *,
        size_t,
        uint8_t const *,
        size_t,
        Out *,
        char *,
        size_t))
{
    Out out{};
    std::array<char, 256> error_buf{};
    auto const rc = verify_fn(
        CONFIDENTIAL_BACKEND_ID,
        bundle.tx_bytes.data(),
        bundle.tx_bytes.size(),
        bundle.artifacts.data(),
        bundle.artifacts.size(),
        &out,
        error_buf.data(),
        error_buf.size());
    EXPECT_EQ(rc, 1) << error_buf.data();
    return out;
}

Result<byte_string> invoke(
    TinyVmConfidentialContract &contract, byte_string const &calldata,
    State &state, Address const &sender, uint64_t const value = 0)
{
    auto view = byte_string_view{calldata.data(), calldata.size()};
    auto const [func, _cost] =
        contract.precompile_dispatch<MonadTraits<MONAD_NEXT>>(view);
    if (value > 0) {
        state.subtract_from_balance(sender, value);
        state.add_to_balance(TINYVM_CONFIDENTIAL_CA, value);
    }
    u256_be value_be{value};
    evmc_uint256be msg_value{};
    std::memcpy(msg_value.bytes, value_be.bytes, sizeof(msg_value.bytes));
    auto result = (contract.*func)(view, sender, msg_value);
    if (result.has_error() && value > 0) {
        state.subtract_from_balance(TINYVM_CONFIDENTIAL_CA, value);
        state.add_to_balance(sender, value);
    }
    if (result.has_value()) {
        return outcome::success(std::move(result.value()));
    }
    return outcome::failure(std::move(result.error()));
}

std::optional<TinyVmConfidentialContract::TokenStorage> load_token(
    State &state, bytes32_t const &token)
{
    StorageVariable<TinyVmConfidentialContract::TokenStorage> var{
        state,
        TINYVM_CONFIDENTIAL_CA,
        TinyVmConfidentialContract::token_storage_key(token)};
    return var.load_checked();
}

std::optional<TinyVmConfidentialContract::AccountStorage> load_account(
    State &state, bytes32_t const &token, Address const &owner)
{
    StorageVariable<TinyVmConfidentialContract::AccountStorage> var{
        state,
        TINYVM_CONFIDENTIAL_CA,
        TinyVmConfidentialContract::account_storage_key(token, owner)};
    return var.load_checked();
}

struct TinyVmConfidentialTest : public ::testing::Test
{
    OnDiskMachine machine;
    vm::VM vm;
    mpt::Db db{machine};
    TrieDb tdb{db};
    BlockState bs{tdb, vm};
    State state{bs, Incarnation{0, 0}};
    NoopCallTracer call_tracer;
    TinyVmConfidentialContract contract{state, call_tracer};
};

} // namespace

TEST_F(TinyVmConfidentialTest, precompile_registers_and_executes_confidential_flow)
{
    auto const fixture = load_fixture();
    state.add_to_balance(fixture.alice, 1'000'000);
    state.add_to_balance(fixture.bob, 1'000'000);

    {
        auto const result = invoke(
            contract,
            make_register_call(fixture.token, fixture.public_asset),
            state,
            fixture.alice);
        ASSERT_TRUE(result.has_value());
        auto const token_cfg = load_token(state, fixture.token);
        ASSERT_TRUE(token_cfg.has_value());
        EXPECT_EQ(token_cfg->public_asset, fixture.public_asset);
        EXPECT_EQ(token_cfg->escrowed_public_amount.native(), 0);
    }

    auto const shield_alice_public = ffi_verify_bundle(
        fixture.shield_alice,
        tinyvm_verify_public_balance_change_backend_call);
    {
        auto const result = invoke(
            contract,
            make_shield_call(
                fixture.shield_alice.tx_bytes,
                fixture.shield_alice.artifacts),
            state,
            fixture.alice,
            shield_alice_public.public_amount);
        ASSERT_TRUE(result.has_value());
        auto const account = load_account(state, fixture.token, fixture.alice);
        auto const token_cfg = load_token(state, fixture.token);
        ASSERT_TRUE(account.has_value());
        ASSERT_TRUE(token_cfg.has_value());
        EXPECT_EQ(account->version.native(), shield_alice_public.version + 1);
        EXPECT_EQ(account->commitment, raw_to_bytes32(shield_alice_public.new_commitment));
        EXPECT_EQ(
            token_cfg->escrowed_public_amount.native(),
            shield_alice_public.public_amount);
    }

    auto const shield_bob_public = ffi_verify_bundle(
        fixture.shield_bob,
        tinyvm_verify_public_balance_change_backend_call);
    {
        auto const result = invoke(
            contract,
            make_shield_call(fixture.shield_bob.tx_bytes, fixture.shield_bob.artifacts),
            state,
            fixture.bob,
            shield_bob_public.public_amount);
        ASSERT_TRUE(result.has_value());
        auto const account = load_account(state, fixture.token, fixture.bob);
        auto const token_cfg = load_token(state, fixture.token);
        ASSERT_TRUE(account.has_value());
        ASSERT_TRUE(token_cfg.has_value());
        EXPECT_EQ(account->version.native(), shield_bob_public.version + 1);
        EXPECT_EQ(account->commitment, raw_to_bytes32(shield_bob_public.new_commitment));
        EXPECT_EQ(
            token_cfg->escrowed_public_amount.native(),
            shield_alice_public.public_amount + shield_bob_public.public_amount);
    }

    auto const transfer_public = ffi_verify_bundle(
        fixture.transfer, tinyvm_verify_transfer_backend_call);
    {
        auto const result = invoke(
            contract,
            make_transfer_call(fixture.transfer.tx_bytes, fixture.transfer.artifacts),
            state,
            fixture.alice);
        ASSERT_TRUE(result.has_value());
        auto const alice = load_account(state, fixture.token, fixture.alice);
        auto const bob = load_account(state, fixture.token, fixture.bob);
        ASSERT_TRUE(alice.has_value());
        ASSERT_TRUE(bob.has_value());
        EXPECT_EQ(alice->version.native(), transfer_public.sender_version + 1);
        EXPECT_EQ(bob->version.native(), transfer_public.recipient_version + 1);
        EXPECT_EQ(
            alice->commitment,
            raw_to_bytes32(transfer_public.sender_new_commitment));
        EXPECT_EQ(
            bob->commitment,
            raw_to_bytes32(transfer_public.recipient_new_commitment));
    }

    auto const unshield_bob_public = ffi_verify_bundle(
        fixture.unshield_bob,
        tinyvm_verify_public_balance_change_backend_call);
    {
        auto const bob_balance_before = state.get_balance(fixture.bob);
        auto const result = invoke(
            contract,
            make_unshield_call(
                fixture.unshield_bob.tx_bytes,
                fixture.unshield_bob.artifacts),
            state,
            fixture.bob);
        ASSERT_TRUE(result.has_value());
        auto const bob = load_account(state, fixture.token, fixture.bob);
        auto const token_cfg = load_token(state, fixture.token);
        ASSERT_TRUE(bob.has_value());
        ASSERT_TRUE(token_cfg.has_value());
        EXPECT_EQ(bob->version.native(), unshield_bob_public.version + 1);
        EXPECT_EQ(
            bob->commitment,
            raw_to_bytes32(unshield_bob_public.new_commitment));
        EXPECT_EQ(
            token_cfg->escrowed_public_amount.native(),
            shield_alice_public.public_amount + shield_bob_public.public_amount -
                unshield_bob_public.public_amount);
        EXPECT_EQ(
            state.get_balance(fixture.bob),
            bob_balance_before + unshield_bob_public.public_amount);
    }
}

TEST_F(TinyVmConfidentialTest, shield_rejects_non_owner_sender)
{
    auto const fixture = load_fixture();
    state.add_to_balance(fixture.alice, 1'000'000);
    state.add_to_balance(fixture.bob, 1'000'000);
    auto const register_result =
        invoke(
            contract,
            make_register_call(fixture.token, fixture.public_asset),
            state,
            fixture.alice);
    ASSERT_TRUE(register_result.has_value());

    auto const result = invoke(
        contract,
        make_shield_call(fixture.shield_alice.tx_bytes, fixture.shield_alice.artifacts),
        state,
        fixture.bob,
        9);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TinyVmConfidentialTest, register_token_is_permissionless_and_mrc20_uses_zero_value)
{
    bytes32_t token{};
    token.bytes[31] = 0x44;
    Address public_asset{};
    public_asset.bytes[19] = 0x99;

    auto const register_result = invoke(
        contract,
        make_register_call(token, public_asset),
        state,
        Address{0x1234});
    ASSERT_TRUE(register_result.has_value());
    auto const token_cfg = load_token(state, token);
    ASSERT_TRUE(token_cfg.has_value());
    EXPECT_EQ(token_cfg->public_asset, public_asset);
    EXPECT_EQ(token_cfg->escrowed_public_amount.native(), 0);
}
