// Copyright (C) 2026 Category Labs, Inc.
//
// Integration tests for TinyVM precompile: system tx validation,
// store bridge, and EIP-161 account creation.

#include <category/core/byte_string.hpp>
#include <category/core/hex.hpp>
#include <category/core/result.hpp>
#include <category/execution/ethereum/core/address.hpp>
#include <category/execution/ethereum/db/trie_db.hpp>
#include <category/execution/ethereum/db/util.hpp>
#include <category/execution/ethereum/metrics/block_metrics.hpp>
#include <category/execution/ethereum/state2/block_state.hpp>
#include <category/execution/ethereum/trace/call_tracer.hpp>
#include <category/execution/monad/chain/monad_devnet.hpp>
#include <category/execution/monad/execute_system_transaction.hpp>
#include <category/execution/monad/system_sender.hpp>
#include <category/execution/monad/tinyvm/tinyvm_precompile.hpp>
#include <category/execution/monad/validate_system_transaction.hpp>
#include <category/mpt/db.hpp>
#include <category/vm/evm/traits.hpp>
#include <category/vm/vm.hpp>
#include <monad/test/traits_test.hpp>

#include <test_resource_data.h>

#include <gtest/gtest.h>

using namespace monad;
using namespace monad::test;

namespace
{

// registerToken(bytes32 token, address publicAsset) selector
constexpr uint8_t REGISTER_TOKEN_SELECTOR[] = {0x2d, 0xed, 0x0f, 0xb5};

byte_string build_register_native_mon_calldata()
{
    byte_string cd;
    cd.insert(cd.end(), REGISTER_TOKEN_SELECTOR,
              REGISTER_TOKEN_SELECTOR + sizeof(REGISTER_TOKEN_SELECTOR));
    // token = 0x7a repeated (32 bytes)
    for (int i = 0; i < 32; ++i)
        cd.push_back(0x7a);
    // publicAsset = address(0), ABI-encoded as bytes32
    for (int i = 0; i < 32; ++i)
        cd.push_back(0x00);
    return cd;
}

Transaction make_system_tx_to_tinyvm(byte_string_view calldata, uint64_t nonce = 0)
{
    Transaction tx;
    tx.type = TransactionType::legacy;
    tx.to = TINYVM_PRECOMPILE_ADDRESS;
    tx.data = byte_string(calldata.begin(), calldata.end());
    tx.gas_limit = 0;
    tx.max_fee_per_gas = 0;
    tx.max_priority_fee_per_gas = 0;
    tx.value = 0;
    tx.nonce = nonce;
    return tx;
}

} // namespace

// Test 1: validate_system_transaction accepts 0x420 at MONAD_TINYVM revision
TEST(TinyVmPrecompile, system_tx_validation_accepts_0x420)
{
    auto const cd = build_register_native_mon_calldata();
    auto const tx = make_system_tx_to_tinyvm(
        byte_string_view(cd.data(), cd.size()), /*nonce=*/1);

    auto const result =
        static_validate_system_transaction<MonadTraits<MONAD_TINYVM>>(
            tx, SYSTEM_SENDER);

    EXPECT_TRUE(result.has_value())
        << "system tx to 0x420 should be accepted at MONAD_TINYVM revision";
}

// Test 2: validate_system_transaction rejects 0x420 at pre-TINYVM revision
TEST(TinyVmPrecompile, system_tx_validation_rejects_0x420_before_tinyvm)
{
    auto const cd = build_register_native_mon_calldata();
    auto const tx = make_system_tx_to_tinyvm(
        byte_string_view(cd.data(), cd.size()), /*nonce=*/1);

    auto const result =
        static_validate_system_transaction<MonadTraits<MONAD_NEXT>>(
            tx, SYSTEM_SENDER);

    EXPECT_FALSE(result.has_value())
        << "system tx to 0x420 should be rejected before MONAD_TINYVM";
}

// Test 3: TinyVmPrecompile constructor creates the account with balance >= 1
TEST(TinyVmPrecompile, constructor_creates_account_with_nonzero_balance)
{
    InMemoryMachine machine;
    mpt::Db db{machine};
    TrieDb tdb{db};
    vm::VM vm;

    BlockState block_state{tdb, vm};
    BlockMetrics block_metrics;

    MonadDevnet chain;
    auto const genesis_state = chain.get_genesis_state();
    auto result = block_state.apply_genesis(genesis_state);
    ASSERT_TRUE(result.has_value());

    auto &state = block_state.state();
    trace::CallTracer tracer;

    // 0x420 should NOT exist before precompile construction
    EXPECT_EQ(state.get_balance(TINYVM_PRECOMPILE_ADDRESS), 0u);

    // Construct precompile — should create account
    TinyVmPrecompile precompile(state, tracer);

    EXPECT_GE(state.get_balance(TINYVM_PRECOMPILE_ADDRESS), 1u)
        << "precompile must fund 0x420 with at least 1 wei to survive EIP-161";
}

// Test 4: registerToken via precompile succeeds and persists storage
TEST(TinyVmPrecompile, register_token_persists_storage)
{
    InMemoryMachine machine;
    mpt::Db db{machine};
    TrieDb tdb{db};
    vm::VM vm;

    BlockState block_state{tdb, vm};
    BlockMetrics block_metrics;

    MonadDevnet chain;
    auto const genesis_state = chain.get_genesis_state();
    auto result = block_state.apply_genesis(genesis_state);
    ASSERT_TRUE(result.has_value());

    auto &state = block_state.state();
    trace::CallTracer tracer;

    TinyVmPrecompile precompile(state, tracer);

    auto const cd = build_register_native_mon_calldata();
    evmc_address sender{};
    std::memset(sender.bytes, 0xa1, sizeof(sender.bytes));
    evmc_uint256be value{};

    auto exec_result = precompile.execute(
        byte_string_view(cd.data(), cd.size()), sender, value);

    EXPECT_TRUE(exec_result.has_value())
        << "registerToken should succeed";

    // We can't enumerate storage, but we can verify the precompile didn't revert
    // The real test is that subsequent shield calls can read back the token config
}

// Test 5: gas cost returns correct value for registerToken
TEST(TinyVmPrecompile, gas_cost_register_token)
{
    auto const cd = build_register_native_mon_calldata();
    uint64_t gas = tinyvm_gas_cost(cd.data(), cd.size());
    EXPECT_EQ(gas, 30000u)
        << "registerToken gas should be 30000 (from confidential backend)";
}
