#include "driver_interface.h"
#include <sstream>

namespace driver {

    // Constants
    namespace constants {
        constexpr SIZE_T MAX_BUFFER_SIZE = 0x100000; // 1MB maximum per operation
    }

    DriverInterface::DriverInterface() 
        : driver_handle(INVALID_HANDLE_VALUE)
        , attached_process_id(0)
        , is_attached(false) {
    }

    DriverInterface::~DriverInterface() {
        Close();
    }

    std::wstring DriverInterface::GetLastErrorMessage() const {
        DWORD error = GetLastError();
        LPWSTR buffer = nullptr;
        
        FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&buffer),
            0,
            nullptr
        );

        std::wstring message;
        if (buffer) {
            message = buffer;
            LocalFree(buffer);
        } else {
            std::wostringstream oss;
            oss << L"Error code: " << error;
            message = oss.str();
        }

        return message;
    }

    bool DriverInterface::ValidateHandle() const {
        return driver_handle != INVALID_HANDLE_VALUE && driver_handle != nullptr;
    }

    Result<bool> DriverInterface::Initialize() {
        if (ValidateHandle()) {
            return Result<bool>(ErrorCode::InvalidParameter, L"Driver already initialized");
        }

        driver_handle = CreateFileW(
            L"\\\\.\\UnderDriver",
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (driver_handle == INVALID_HANDLE_VALUE) {
            return Result<bool>(ErrorCode::DeviceNotFound, 
                              L"Failed to open driver: " + GetLastErrorMessage());
        }

        return Result<bool>(true);
    }

    void DriverInterface::Close() {
        if (ValidateHandle()) {
            CloseHandle(driver_handle);
            driver_handle = INVALID_HANDLE_VALUE;
        }
        is_attached = false;
        attached_process_id = 0;
    }

    Result<bool> DriverInterface::AttachToProcess(DWORD process_id) {
        if (!ValidateHandle()) {
            return Result<bool>(ErrorCode::InvalidHandle, L"Invalid driver handle");
        }

        if (process_id == 0) {
            return Result<bool>(ErrorCode::InvalidParameter, L"Invalid process ID");
        }

        Request r = {};
        r.process_id = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(process_id));

        DWORD bytes_returned = 0;
        BOOL result = DeviceIoControl(
            driver_handle,
            codes::attach,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            &bytes_returned,
            nullptr
        );

        if (!result) {
            return Result<bool>(ErrorCode::OperationFailed, 
                              L"Failed to attach to process: " + GetLastErrorMessage());
        }

        is_attached = true;
        attached_process_id = process_id;

        return Result<bool>(true);
    }

    void DriverInterface::Detach() {
        is_attached = false;
        attached_process_id = 0;
    }

    Result<std::vector<BYTE>> DriverInterface::ReadMemoryBuffer(std::uintptr_t address, SIZE_T size) {
        if (!ValidateHandle()) {
            return Result<std::vector<BYTE>>(ErrorCode::InvalidHandle, L"Invalid driver handle");
        }

        if (!is_attached) {
            return Result<std::vector<BYTE>>(ErrorCode::InvalidParameter, L"Not attached to any process");
        }

        if (size == 0 || size > constants::MAX_BUFFER_SIZE) {
            return Result<std::vector<BYTE>>(ErrorCode::InvalidParameter, L"Invalid buffer size");
        }

        std::vector<BYTE> buffer(size);
        Request r = {};
        r.target = reinterpret_cast<PVOID>(address);
        r.buffer = buffer.data();
        r.size = size;

        DWORD bytes_returned = 0;
        BOOL result = DeviceIoControl(driver_handle, codes::read, &r, sizeof(r), 
                                      &r, sizeof(r), &bytes_returned, nullptr);

        if (!result) {
            return Result<std::vector<BYTE>>(ErrorCode::OperationFailed, 
                                            L"Failed to read memory buffer: " + GetLastErrorMessage());
        }

        return Result<std::vector<BYTE>>(buffer);
    }

    Result<bool> DriverInterface::WriteMemoryBuffer(std::uintptr_t address, const void* data, SIZE_T size) {
        if (!ValidateHandle()) {
            return Result<bool>(ErrorCode::InvalidHandle, L"Invalid driver handle");
        }

        if (!is_attached) {
            return Result<bool>(ErrorCode::InvalidParameter, L"Not attached to any process");
        }

        if (data == nullptr || size == 0 || size > constants::MAX_BUFFER_SIZE) {
            return Result<bool>(ErrorCode::InvalidParameter, L"Invalid buffer parameters");
        }

        Request r = {};
        r.target = reinterpret_cast<PVOID>(address);
        r.buffer = const_cast<PVOID>(data);
        r.size = size;

        DWORD bytes_returned = 0;
        BOOL result = DeviceIoControl(driver_handle, codes::write, &r, sizeof(r), 
                                      &r, sizeof(r), &bytes_returned, nullptr);

        if (!result) {
            return Result<bool>(ErrorCode::OperationFailed, 
                              L"Failed to write memory buffer: " + GetLastErrorMessage());
        }

        return Result<bool>(true);
    }

    Result<ProcessInfo> DriverInterface::GetProcessInfo(DWORD process_id) {
        if (!ValidateHandle()) {
            return Result<ProcessInfo>(ErrorCode::InvalidHandle, L"Invalid driver handle");
        }

        if (process_id == 0) {
            return Result<ProcessInfo>(ErrorCode::InvalidParameter, L"Invalid process ID");
        }

        ProcessInfo info = {};
        info.process_id = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(process_id));

        DWORD bytes_returned = 0;
        BOOL result = DeviceIoControl(
            driver_handle,
            codes::get_process_info,
            &info,
            sizeof(info),
            &info,
            sizeof(info),
            &bytes_returned,
            nullptr
        );

        if (!result) {
            return Result<ProcessInfo>(ErrorCode::OperationFailed, 
                                      L"Failed to get process info: " + GetLastErrorMessage());
        }

        return Result<ProcessInfo>(info);
    }

    Result<TokenValidation> DriverInterface::ValidateSecurityToken(DWORD process_id) {
        if (!ValidateHandle()) {
            return Result<TokenValidation>(ErrorCode::InvalidHandle, L"Invalid driver handle");
        }

        if (process_id == 0) {
            return Result<TokenValidation>(ErrorCode::InvalidParameter, L"Invalid process ID");
        }

        TokenValidation token = {};
        token.process_id = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(process_id));

        DWORD bytes_returned = 0;
        BOOL result = DeviceIoControl(
            driver_handle,
            codes::validate_token,
            &token,
            sizeof(token),
            &token,
            sizeof(token),
            &bytes_returned,
            nullptr
        );

        if (!result) {
            return Result<TokenValidation>(ErrorCode::OperationFailed, 
                                          L"Failed to validate security token: " + GetLastErrorMessage());
        }

        return Result<TokenValidation>(token);
    }

} // namespace driver
