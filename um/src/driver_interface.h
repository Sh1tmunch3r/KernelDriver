#pragma once

#ifndef DRIVER_INTERFACE_H
#define DRIVER_INTERFACE_H

#include <Windows.h>
#include <string>
#include <memory>
#include <vector>

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
        NotImplemented = 7,
        InvalidHandle = 8,
        DeviceNotFound = 9
    };

    // Result structure for operations
    template<typename T>
    struct Result {
        ErrorCode error_code;
        std::wstring error_message;
        T value;
        bool success;

        Result() : error_code(ErrorCode::Success), success(true), value{} {}
        Result(ErrorCode code, const std::wstring& msg) 
            : error_code(code), error_message(msg), success(false), value{} {}
        Result(const T& val) 
            : error_code(ErrorCode::Success), success(true), value(val) {}
    };

    // Main driver interface class
    class DriverInterface {
    private:
        HANDLE driver_handle;
        DWORD attached_process_id;
        bool is_attached;

        // Helper function to get last error message
        std::wstring GetLastErrorMessage() const;

        // Helper function to validate handle
        bool ValidateHandle() const;

    public:
        DriverInterface();
        ~DriverInterface();

        // Disable copy
        DriverInterface(const DriverInterface&) = delete;
        DriverInterface& operator=(const DriverInterface&) = delete;

        // Initialize the driver connection
        Result<bool> Initialize();

        // Close the driver connection
        void Close();

        // Attach to a process
        Result<bool> AttachToProcess(DWORD process_id);

        // Detach from current process
        void Detach();

        // Read memory from attached process
        template<typename T>
        Result<T> ReadMemory(std::uintptr_t address);

        // Read memory buffer from attached process
        Result<std::vector<BYTE>> ReadMemoryBuffer(std::uintptr_t address, SIZE_T size);

        // Write memory to attached process
        template<typename T>
        Result<bool> WriteMemory(std::uintptr_t address, const T& value);

        // Write memory buffer to attached process
        Result<bool> WriteMemoryBuffer(std::uintptr_t address, const void* data, SIZE_T size);

        // Get process information
        Result<ProcessInfo> GetProcessInfo(DWORD process_id);

        // Validate security token
        Result<TokenValidation> ValidateSecurityToken(DWORD process_id);

        // Check if attached to a process
        bool IsAttached() const { return is_attached; }

        // Get attached process ID
        DWORD GetAttachedProcessId() const { return attached_process_id; }

        // Get driver handle
        HANDLE GetHandle() const { return driver_handle; }
    };

    // Template implementations
    template<typename T>
    Result<T> DriverInterface::ReadMemory(std::uintptr_t address) {
        if (!ValidateHandle()) {
            return Result<T>(ErrorCode::InvalidHandle, L"Invalid driver handle");
        }

        if (!is_attached) {
            return Result<T>(ErrorCode::InvalidParameter, L"Not attached to any process");
        }

        T temp = {};
        Request r = {};
        r.target = reinterpret_cast<PVOID>(address);
        r.buffer = &temp;
        r.size = sizeof(T);

        DWORD bytes_returned = 0;
        BOOL result = DeviceIoControl(driver_handle, codes::read, &r, sizeof(r), 
                                      &r, sizeof(r), &bytes_returned, nullptr);

        if (!result) {
            return Result<T>(ErrorCode::OperationFailed, 
                           L"Failed to read memory: " + GetLastErrorMessage());
        }

        return Result<T>(temp);
    }

    template<typename T>
    Result<bool> DriverInterface::WriteMemory(std::uintptr_t address, const T& value) {
        if (!ValidateHandle()) {
            return Result<bool>(ErrorCode::InvalidHandle, L"Invalid driver handle");
        }

        if (!is_attached) {
            return Result<bool>(ErrorCode::InvalidParameter, L"Not attached to any process");
        }

        Request r = {};
        r.target = reinterpret_cast<PVOID>(address);
        r.buffer = const_cast<PVOID>(static_cast<const void*>(&value));
        r.size = sizeof(T);

        DWORD bytes_returned = 0;
        BOOL result = DeviceIoControl(driver_handle, codes::write, &r, sizeof(r), 
                                      &r, sizeof(r), &bytes_returned, nullptr);

        if (!result) {
            return Result<bool>(ErrorCode::OperationFailed, 
                              L"Failed to write memory: " + GetLastErrorMessage());
        }

        return Result<bool>(true);
    }

} // namespace driver

#endif // DRIVER_INTERFACE_H
