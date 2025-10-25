#pragma once

#ifndef DRIVER_CODES_H
#define DRIVER_CODES_H

#include <Windows.h>

namespace driver {
    namespace codes {
        // Used to setup the driver (attach to process)
        constexpr ULONG attach =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        // Read process memory
        constexpr ULONG read =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        // Write process memory
        constexpr ULONG write =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        // Execute process (new functionality - not implemented for security reasons)
        // TODO: Implement with proper security controls if needed
        constexpr ULONG execute =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x699, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        // Get process info
        constexpr ULONG get_process_info =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x69A, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        // Validate security token
        constexpr ULONG validate_token =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x69B, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    } // namespace codes

    // Shared between user mode & kernel mode
    struct Request {
        HANDLE process_id;

        PVOID target;
        PVOID buffer;

        SIZE_T size;
        SIZE_T return_size;
    };

    // Process execution request structure
    struct ExecuteRequest {
        HANDLE parent_process_id;
        WCHAR executable_path[260];  // MAX_PATH
        WCHAR command_line[512];
        ULONG creation_flags;
        HANDLE created_process_id;
        NTSTATUS status;
    };

    // Process information structure
    struct ProcessInfo {
        HANDLE process_id;
        WCHAR process_name[260];
        ULONG session_id;
        BOOLEAN is_protected;
        NTSTATUS status;
    };

    // Security token validation structure
    struct TokenValidation {
        HANDLE process_id;
        BOOLEAN is_elevated;
        BOOLEAN is_admin;
        NTSTATUS status;
    };

    // Error codes
    enum class ErrorCode : ULONG {
        Success = 0,
        InvalidParameter = 1,
        AccessDenied = 2,
        ProcessNotFound = 3,
        InsufficientPrivileges = 4,
        InvalidBuffer = 5,
        OperationFailed = 6,
        NotImplemented = 7
    };

} // namespace driver

#endif // DRIVER_CODES_H
