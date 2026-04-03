// Copyright (C) 2026 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#include <category/execution/monad/tinyvm_confidential/tinyvm_confidential_error.hpp>

#if __has_include(<boost/outcome/experimental/status-code/status-code/config.hpp>)
    #include <boost/outcome/experimental/status-code/status-code/config.hpp>
    #include <boost/outcome/experimental/status-code/status-code/generic_code.hpp>
    #include <boost/outcome/experimental/status-code/status-code/quick_status_code_from_enum.hpp>
#else
    #include <boost/outcome/experimental/status-code/config.hpp>
    #include <boost/outcome/experimental/status-code/quick_status_code_from_enum.hpp>
#endif

BOOST_OUTCOME_SYSTEM_ERROR2_NAMESPACE_BEGIN

std::initializer_list<
    quick_status_code_from_enum<monad::TinyVmConfidentialError>::mapping> const &
quick_status_code_from_enum<monad::TinyVmConfidentialError>::value_mappings()
{
    using monad::TinyVmConfidentialError;

    static std::initializer_list<mapping> const v = {
        {TinyVmConfidentialError::Success, "success", {errc::success}},
        {TinyVmConfidentialError::MethodNotSupported, "method not supported", {}},
        {TinyVmConfidentialError::ValueNonZero, "value is nonzero", {}},
        {TinyVmConfidentialError::InvalidInput, "input is invalid", {}},
        {TinyVmConfidentialError::VerificationFailed, "proof verification failed", {}},
        {TinyVmConfidentialError::TokenNotRegistered, "token not registered", {}},
        {TinyVmConfidentialError::TokenAlreadyRegistered, "token already registered", {}},
        {TinyVmConfidentialError::SenderMismatch, "sender mismatch", {}},
        {TinyVmConfidentialError::VersionMismatch, "version mismatch", {}},
        {TinyVmConfidentialError::CommitmentMismatch, "commitment mismatch", {}},
        {TinyVmConfidentialError::MissingAccount, "missing account", {}},
        {TinyVmConfidentialError::InvalidKind, "invalid public balance-change kind", {}},
        {TinyVmConfidentialError::InsufficientEscrow, "insufficient public escrow", {}},
    };

    return v;
}

BOOST_OUTCOME_SYSTEM_ERROR2_NAMESPACE_END
