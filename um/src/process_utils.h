#pragma once

#ifndef PROCESS_UTILS_H
#define PROCESS_UTILS_H

#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>

namespace utils {

    // Structure to hold process information
    struct ProcessEntry {
        DWORD process_id;
        std::wstring process_name;
        std::wstring executable_path;
    };

    // Get process ID by name
    DWORD GetProcessId(const wchar_t* process_name);

    // Get module base address
    std::uintptr_t GetModuleBase(DWORD pid, const wchar_t* module_name);

    // List all running processes
    std::vector<ProcessEntry> ListProcesses();

    // Check if process exists
    bool ProcessExists(DWORD process_id);

    // Check if process exists by name
    bool ProcessExistsByName(const wchar_t* process_name);

    // Get process name from ID
    std::wstring GetProcessName(DWORD process_id);

    // Check if current process has admin privileges
    bool IsRunningAsAdmin();

    // Enable debug privileges for current process
    bool EnableDebugPrivilege();

    // Validate process ID
    bool ValidateProcessId(DWORD process_id);

} // namespace utils

#endif // PROCESS_UTILS_H
