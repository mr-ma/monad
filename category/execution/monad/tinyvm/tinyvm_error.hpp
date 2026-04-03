// Copyright (C) 2026 Category Labs, Inc.

#pragma once

#include <category/core/config.hpp>
#include <category/core/result.hpp>
#include <system_error>

MONAD_NAMESPACE_BEGIN

enum class TinyVmPrecompileError
{
    Success = 0,
    MethodNotSupported,
    InvalidInput,
    VerificationFailed,
};

MONAD_NAMESPACE_END

SYSTEM_ERROR2_NAMESPACE_BEGIN
template <>
struct quick_status_code_from_enum<monad::TinyVmPrecompileError>
    : quick_status_code_from_enum_defaults<monad::TinyVmPrecompileError>
{
    static constexpr auto domain_name = "tinyvm precompile error";
    static constexpr auto value_string = "tinyvm precompile error value";
    using Base = quick_status_code_from_enum_defaults<monad::TinyVmPrecompileError>;
    using mapping = Base::mapping;
    static inline std::initializer_list<mapping> const &value_mappings()
    {
        using monad::TinyVmPrecompileError;
        static std::initializer_list<mapping> const v = {
            {TinyVmPrecompileError::Success, "success", {errc::success}},
            {TinyVmPrecompileError::MethodNotSupported, "method not supported", {}},
            {TinyVmPrecompileError::InvalidInput, "input is invalid", {}},
            {TinyVmPrecompileError::VerificationFailed, "verification failed", {}},
        };
        return v;
    }
};
SYSTEM_ERROR2_NAMESPACE_END
