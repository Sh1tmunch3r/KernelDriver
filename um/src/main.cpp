#include <iostream>
#include <iomanip>
#include "driver_interface.h"
#include "process_utils.h"

// Display error message
void DisplayError(const std::wstring& operation, const driver::ErrorCode& error_code, const std::wstring& message) {
	std::wcout << L"[ERROR] " << operation << L" failed" << std::endl;
	std::wcout << L"  Error Code: " << static_cast<ULONG>(error_code) << std::endl;
	std::wcout << L"  Message: " << message << std::endl;
}

// Display success message
void DisplaySuccess(const std::wstring& operation) {
	std::wcout << L"[SUCCESS] " << operation << std::endl;
}

// Display process information
void DisplayProcessInfo(const driver::ProcessInfo& info) {
	std::wcout << L"Process Information:" << std::endl;
	std::wcout << L"  Process ID: " << static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(info.process_id)) << std::endl;
	std::wcout << L"  Session ID: " << info.session_id << std::endl;
	std::wcout << L"  Protected: " << (info.is_protected ? L"Yes" : L"No") << std::endl;
}

// Demonstrate basic memory operations
void DemoMemoryOperations(driver::DriverInterface& driver_iface, DWORD pid) {
	std::wcout << L"\n=== Memory Operations Demo ===" << std::endl;

	// Attach to process
	auto attach_result = driver_iface.AttachToProcess(pid);
	if (!attach_result.success) {
		DisplayError(L"Attach to process", attach_result.error_code, attach_result.error_message);
		return;
	}
	DisplaySuccess(L"Attached to process");

	// Read an integer from address 0x1000 (example - may not be valid)
	std::wcout << L"\nAttempting to read memory..." << std::endl;
	auto read_result = driver_iface.ReadMemory<int>(0x1000);
	if (read_result.success) {
		std::wcout << L"  Read value: " << read_result.value << std::endl;
	} else {
		std::wcout << L"  Read failed (expected - address may not be valid)" << std::endl;
	}

	driver_iface.Detach();
	DisplaySuccess(L"Detached from process");
}

// Display menu
void DisplayMenu() {
	std::wcout << L"\n=== UnderDriver User Mode Interface ===" << std::endl;
	std::wcout << L"1. List running processes" << std::endl;
	std::wcout << L"2. Attach to process by name" << std::endl;
	std::wcout << L"3. Get process information" << std::endl;
	std::wcout << L"4. Validate security token" << std::endl;
	std::wcout << L"5. Check admin privileges" << std::endl;
	std::wcout << L"6. Enable debug privilege" << std::endl;
	std::wcout << L"7. Exit" << std::endl;
	std::wcout << L"Select option: ";
}

int main() {
	std::wcout << L"[+] UnderDriver User Mode Application [+]" << std::endl;
	std::wcout << L"Version: 2.0 - Enhanced Interface" << std::endl;

	// Check admin privileges
	if (utils::IsRunningAsAdmin()) {
		DisplaySuccess(L"Running with administrator privileges");
	} else {
		std::wcout << L"[WARNING] Not running as administrator - some operations may fail" << std::endl;
	}

	// Initialize driver interface
	driver::DriverInterface driver_iface;
	auto init_result = driver_iface.Initialize();
	
	if (!init_result.success) {
		DisplayError(L"Driver initialization", init_result.error_code, init_result.error_message);
		std::wcout << L"\nPress Enter to exit...";
		std::wcin.get();
		return 1;
	}
	DisplaySuccess(L"Driver interface initialized");

	// Enable debug privilege
	if (utils::EnableDebugPrivilege()) {
		DisplaySuccess(L"Debug privilege enabled");
	} else {
		std::wcout << L"[WARNING] Failed to enable debug privilege" << std::endl;
	}

	// Interactive menu loop
	bool running = true;
	while (running) {
		DisplayMenu();
		
		int choice = 0;
		std::wcin >> choice;
		std::wcin.ignore();

		switch (choice) {
			case 1: {
				std::wcout << L"\n=== Running Processes ===" << std::endl;
				auto processes = utils::ListProcesses();
				std::wcout << L"Total processes: " << processes.size() << std::endl;
				std::wcout << L"Showing first 20 processes:" << std::endl;
				
				int count = 0;
				for (const auto& proc : processes) {
					if (count++ >= 20) break;
					std::wcout << L"  PID: " << std::setw(6) << proc.process_id 
							  << L" | " << proc.process_name << std::endl;
				}
				break;
			}

			case 2: {
				std::wcout << L"\nEnter process name (e.g., notepad.exe): ";
				std::wstring proc_name;
				std::getline(std::wcin, proc_name);

				DWORD pid = utils::GetProcessId(proc_name.c_str());
				if (pid == 0) {
					std::wcout << L"[ERROR] Process not found" << std::endl;
				} else {
					std::wcout << L"Found process with PID: " << pid << std::endl;
					auto attach_result = driver_iface.AttachToProcess(pid);
					if (attach_result.success) {
						DisplaySuccess(L"Attached to process");
						std::wcout << L"Note: Call detach before attaching to another process" << std::endl;
					} else {
						DisplayError(L"Attach", attach_result.error_code, attach_result.error_message);
					}
				}
				break;
			}

			case 3: {
				std::wcout << L"\nEnter process ID: ";
				DWORD pid = 0;
				std::wcin >> pid;
				std::wcin.ignore();

				if (!utils::ValidateProcessId(pid)) {
					std::wcout << L"[ERROR] Invalid or non-existent process ID" << std::endl;
				} else {
					auto info_result = driver_iface.GetProcessInfo(pid);
					if (info_result.success) {
						DisplayProcessInfo(info_result.value);
					} else {
						DisplayError(L"Get process info", info_result.error_code, info_result.error_message);
					}
				}
				break;
			}

			case 4: {
				std::wcout << L"\nEnter process ID: ";
				DWORD pid = 0;
				std::wcin >> pid;
				std::wcin.ignore();

				if (!utils::ValidateProcessId(pid)) {
					std::wcout << L"[ERROR] Invalid or non-existent process ID" << std::endl;
				} else {
					auto token_result = driver_iface.ValidateSecurityToken(pid);
					if (token_result.success) {
						std::wcout << L"Security Token Information:" << std::endl;
						std::wcout << L"  Elevated: " << (token_result.value.is_elevated ? L"Yes" : L"No") << std::endl;
						std::wcout << L"  Admin: " << (token_result.value.is_admin ? L"Yes" : L"No") << std::endl;
					} else {
						DisplayError(L"Validate token", token_result.error_code, token_result.error_message);
					}
				}
				break;
			}

			case 5: {
				if (utils::IsRunningAsAdmin()) {
					std::wcout << L"[INFO] Running with administrator privileges" << std::endl;
				} else {
					std::wcout << L"[INFO] Not running with administrator privileges" << std::endl;
				}
				break;
			}

			case 6: {
				if (utils::EnableDebugPrivilege()) {
					DisplaySuccess(L"Debug privilege enabled");
				} else {
					std::wcout << L"[ERROR] Failed to enable debug privilege" << std::endl;
				}
				break;
			}

			case 7: {
				running = false;
				std::wcout << L"Exiting..." << std::endl;
				break;
			}

			default: {
				std::wcout << L"[ERROR] Invalid option" << std::endl;
				break;
			}
		}
	}

	// Cleanup
	driver_iface.Close();
	std::wcout << L"\n[+] Driver interface closed [+]" << std::endl;

	return 0;
}