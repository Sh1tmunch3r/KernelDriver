#include "process_utils.h"
#include <Psapi.h>

namespace utils {

    // Constants
    namespace {
        constexpr DWORD SYSTEM_PROCESS_ID = 4; // Windows System process
    }

    DWORD GetProcessId(const wchar_t* process_name) {
        if (process_name == nullptr) {
            return 0;
        }

        DWORD process_id = 0;
        HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (snap_shot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snap_shot, &entry)) {
            do {
                if (_wcsicmp(process_name, entry.szExeFile) == 0) {
                    process_id = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap_shot, &entry));
        }

        CloseHandle(snap_shot);
        return process_id;
    }

    std::uintptr_t GetModuleBase(DWORD pid, const wchar_t* module_name) {
        if (module_name == nullptr || pid == 0) {
            return 0;
        }

        std::uintptr_t module_base = 0;
        HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        
        if (snap_shot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        MODULEENTRY32W entry = {};
        entry.dwSize = sizeof(MODULEENTRY32W);

        if (Module32FirstW(snap_shot, &entry)) {
            do {
                if (wcsstr(entry.szModule, module_name) != nullptr) {
                    module_base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
                    break;
                }
            } while (Module32NextW(snap_shot, &entry));
        }

        CloseHandle(snap_shot);
        return module_base;
    }

    std::vector<ProcessEntry> ListProcesses() {
        std::vector<ProcessEntry> processes;
        HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (snap_shot == INVALID_HANDLE_VALUE) {
            return processes;
        }

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snap_shot, &entry)) {
            do {
                ProcessEntry proc;
                proc.process_id = entry.th32ProcessID;
                proc.process_name = entry.szExeFile;
                proc.executable_path = entry.szExeFile;
                processes.push_back(proc);
            } while (Process32NextW(snap_shot, &entry));
        }

        CloseHandle(snap_shot);
        return processes;
    }

    bool ProcessExists(DWORD process_id) {
        if (process_id == 0) {
            return false;
        }

        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);
        if (process == nullptr) {
            return false;
        }

        DWORD exit_code = 0;
        bool exists = GetExitCodeProcess(process, &exit_code) && exit_code == STILL_ACTIVE;
        CloseHandle(process);
        
        return exists;
    }

    bool ProcessExistsByName(const wchar_t* process_name) {
        return GetProcessId(process_name) != 0;
    }

    std::wstring GetProcessName(DWORD process_id) {
        if (process_id == 0) {
            return L"";
        }

        HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap_shot == INVALID_HANDLE_VALUE) {
            return L"";
        }

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(PROCESSENTRY32W);
        std::wstring name;

        if (Process32FirstW(snap_shot, &entry)) {
            do {
                if (entry.th32ProcessID == process_id) {
                    name = entry.szExeFile;
                    break;
                }
            } while (Process32NextW(snap_shot, &entry));
        }

        CloseHandle(snap_shot);
        return name;
    }

    bool IsRunningAsAdmin() {
        BOOL is_admin = FALSE;
        PSID admin_group = nullptr;
        SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

        if (AllocateAndInitializeSid(&nt_authority, 2, 
                                     SECURITY_BUILTIN_DOMAIN_RID,
                                     DOMAIN_ALIAS_RID_ADMINS,
                                     0, 0, 0, 0, 0, 0, &admin_group)) {
            CheckTokenMembership(nullptr, admin_group, &is_admin);
            FreeSid(admin_group);
        }

        return is_admin != FALSE;
    }

    bool EnableDebugPrivilege() {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
            return false;
        }

        TOKEN_PRIVILEGES privileges = {};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid)) {
            CloseHandle(token);
            return false;
        }

        bool success = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), 
                                            nullptr, nullptr) != FALSE;
        CloseHandle(token);
        
        return success && GetLastError() == ERROR_SUCCESS;
    }

    bool ValidateProcessId(DWORD process_id) {
        if (process_id == 0 || process_id == SYSTEM_PROCESS_ID) {
            return false;
        }
        return ProcessExists(process_id);
    }

} // namespace utils
