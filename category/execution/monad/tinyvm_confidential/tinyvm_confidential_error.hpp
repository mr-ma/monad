// Copyright (C) 2026 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#pragma once

#include <category/core/config.hpp>

#if __has_include(<boost/outcome/experimental/status-code/status-code/config.hpp>)
    #include <boost/outcome/experimental/status-code/status-code/config.hpp>
    #include <boost/outcome/experimental/status-code/status-code/quick_status_code_from_enum.hpp>
#else
    #include <boost/outcome/experimental/status-code/config.hpp>
    #include <boost/outcome/experimental/status-code/quick_status_code_from_enum.hpp>
#endif

#include <initializer_list>

MONAD_NAMESPACE_BEGIN

enum class TinyVmConfidentialError
{
    Success = 0,
    MethodNotSupported,
    ValueNonZero,
    InvalidInput,
    VerificationFailed,
    TokenNotRegistered,
    TokenAlreadyRegistered,
    SenderMismatch,
    VersionMismatch,
    CommitmentMismatch,
    MissingAccount,
    InvalidKind,
    InsufficientEscrow,
};

MONAD_NAMESPACE_END

BOOST_OUTCOME_SYSTEM_ERROR2_NAMESPACE_BEGIN

template <>
struct quick_status_code_from_enum<monad::TinyVmConfidentialError>
    : quick_status_code_from_enum_defaults<monad::TinyVmConfidentialError>
{
    static constexpr auto const domain_name = "TinyVm Confidential Error";
    static constexpr auto const domain_uuid =
        "3a0db4a8-5793-4f43-a111-c5e4c1ab6d61";

    static std::initializer_list<mapping> const &value_mappings();
};

BOOST_OUTCOME_SYSTEM_ERROR2_NAMESPACE_END
