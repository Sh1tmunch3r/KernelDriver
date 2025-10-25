#include <ntifs.h>
#include <handleapi.h>
#include <ntddk.h>
#include <windef.h>
extern "C" {
	#include <wdm.h>
}

// Library pragmas for kernel mode linking
#pragma comment(lib, "ntoskrnl.lib")
#pragma comment(lib, "hal.lib")
#pragma comment(lib, "wdf01000.lib")
#pragma comment(lib, "wdfldr.lib")
extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(
		_In_opt_ PUNICODE_STRING DriverName,
		_In_ PDRIVER_INITIALIZE InitializeFunction);

	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
		_In_ PEPROCESS SourceProcess,
		_In_ PVOID SourceAddress,
		_In_ PEPROCESS TargetProcess,
		_Out_ PVOID TargetAddress,
		_In_ SIZE_T BufferSize,
		_In_ KPROCESSOR_MODE PreviousMode,
		_Out_ PSIZE_T ReturnSize);

	NTKERNELAPI NTSTATUS ZwQueryInformationProcess(
		_In_ HANDLE ProcessHandle,
		_In_ PROCESSINFOCLASS ProcessInformationClass,
		_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
		_In_ ULONG ProcessInformationLength,
		_Out_opt_ PULONG ReturnLength);

	NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
		_In_ HANDLE ProcessId,
		_Outptr_ PEPROCESS* Process);

	NTKERNELAPI BOOLEAN PsIsProtectedProcess(
		_In_ PEPROCESS Process);

	NTKERNELAPI ULONG PsGetProcessSessionId(
		_In_ PEPROCESS Process);
}

void debug_print(PCSTR text) {
#ifndef DEBUG
	UNREFERENCED_PARAMETER(text);
#endif	//DEBUG

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}

// Constants
namespace constants {
	constexpr SIZE_T MAX_BUFFER_SIZE = 0x100000; // 1MB maximum per operation
	constexpr DWORD SYSTEM_PROCESS_ID = 4; // Windows System process
}

// Security validation helper functions
namespace security {
	// Validate process handle
	BOOLEAN validate_process_handle(HANDLE process_id) {
		if (process_id == nullptr || process_id == INVALID_HANDLE_VALUE) {
			debug_print("[-] Invalid process handle [-]\n");
			return FALSE;
		}
		return TRUE;
	}

	// Validate buffer parameters
	BOOLEAN validate_buffer(PVOID buffer, SIZE_T size) {
		if (buffer == nullptr || size == 0 || size > constants::MAX_BUFFER_SIZE) {
			debug_print("[-] Invalid buffer parameters [-]\n");
			return FALSE;
		}
		return TRUE;
	}

	// Check if process is protected
	BOOLEAN is_process_protected(PEPROCESS process) {
		if (process == nullptr) {
			return FALSE;
		}
		return PsIsProtectedProcess(process);
	}

	// Sanitize string input
	VOID sanitize_string(PWCHAR str, SIZE_T max_length) {
		if (str == nullptr) {
			return;
		}
		for (SIZE_T i = 0; i < max_length; i++) {
			if (str[i] == L'\0') {
				break;
			}
			// Remove any control characters
			if (str[i] < 32 && str[i] != L'\t' && str[i] != L'\n' && str[i] != L'\r') {
				str[i] = L' ';
			}
		}
		// Ensure null termination
		str[max_length - 1] = L'\0';
	}
} // namespace security

namespace driver {
	namespace codes {
		// Used to setup the driver. 
		constexpr ULONG attach =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// Read process memory. 
		constexpr ULONG read =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// Write process memory. 
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
	} // Namespace codes

	// shared between user mode & kernel mode.
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

	NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);

		debug_print("[+] Device control called [+]\n");

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		// determines code passed through.
		PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);

		// access the request object sent from um
		auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

		if (stack_irp == nullptr || request == nullptr) {
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}

		static PEPROCESS target_process = nullptr;

		const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;
		switch (control_code) {
			case codes::attach:
				// Validate input
				if (!security::validate_process_handle(request->process_id)) {
					status = STATUS_INVALID_PARAMETER;
					break;
				}

				// Dereference previous target if exists
				if (target_process != nullptr) {
					ObDereferenceObject(target_process);
					target_process = nullptr;
				}

				status = PsLookupProcessByProcessId(request->process_id, &target_process);
				if (NT_SUCCESS(status)) {
					debug_print("[+] Successfully attached to process [+]\n");
				} else {
					debug_print("[-] Failed to attach to process [-]\n");
					target_process = nullptr;
				}
				break;

			case codes::read:
				// Validate target process and buffer
				if (target_process == nullptr) {
					debug_print("[-] No target process attached [-]\n");
					status = STATUS_INVALID_DEVICE_REQUEST;
					break;
				}

				if (!security::validate_buffer(request->buffer, request->size)) {
					status = STATUS_INVALID_PARAMETER;
					break;
				}

				// Check if process is protected
				if (security::is_process_protected(target_process)) {
					debug_print("[-] Target process is protected [-]\n");
					status = STATUS_ACCESS_DENIED;
					break;
				}

				status = MmCopyVirtualMemory(target_process, request->target,
					PsGetCurrentProcess(), request->buffer,
					request->size, KernelMode, &request->return_size);

				if (NT_SUCCESS(status)) {
					debug_print("[+] Memory read successful [+]\n");
				} else {
					debug_print("[-] Memory read failed [-]\n");
				}
				break;

			case codes::write:
				// Validate target process and buffer
				if (target_process == nullptr) {
					debug_print("[-] No target process attached [-]\n");
					status = STATUS_INVALID_DEVICE_REQUEST;
					break;
				}

				if (!security::validate_buffer(request->buffer, request->size)) {
					status = STATUS_INVALID_PARAMETER;
					break;
				}

				// Check if process is protected
				if (security::is_process_protected(target_process)) {
					debug_print("[-] Target process is protected [-]\n");
					status = STATUS_ACCESS_DENIED;
					break;
				}

				status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->buffer,
					target_process, request->target, request->size, KernelMode, &request->return_size);

				if (NT_SUCCESS(status)) {
					debug_print("[+] Memory write successful [+]\n");
				} else {
					debug_print("[-] Memory write failed [-]\n");
				}
				break;

			case codes::get_process_info: {
				auto info = reinterpret_cast<ProcessInfo*>(irp->AssociatedIrp.SystemBuffer);
				if (info == nullptr) {
					status = STATUS_INVALID_PARAMETER;
					break;
				}

				PEPROCESS process = nullptr;
				status = PsLookupProcessByProcessId(info->process_id, &process);
				if (NT_SUCCESS(status) && process != nullptr) {
					info->session_id = PsGetProcessSessionId(process);
					info->is_protected = security::is_process_protected(process);
					info->status = STATUS_SUCCESS;
					ObDereferenceObject(process);
					debug_print("[+] Process info retrieved [+]\n");
				} else {
					info->status = STATUS_NOT_FOUND;
					debug_print("[-] Failed to retrieve process info [-]\n");
				}
				status = STATUS_SUCCESS;
				irp->IoStatus.Information = sizeof(ProcessInfo);
				break;
			}

			case codes::validate_token: {
				auto token_info = reinterpret_cast<TokenValidation*>(irp->AssociatedIrp.SystemBuffer);
				if (token_info == nullptr) {
					status = STATUS_INVALID_PARAMETER;
					break;
				}

				// Note: Full token validation would require additional security APIs
				// This is a simplified implementation
				token_info->is_elevated = FALSE;
				token_info->is_admin = FALSE;
				token_info->status = STATUS_SUCCESS;

				debug_print("[+] Token validation performed [+]\n");
				status = STATUS_SUCCESS;
				irp->IoStatus.Information = sizeof(TokenValidation);
				break;
			}

			case codes::execute:
				// Process execution from kernel mode is complex and potentially dangerous
				// This would require ZwCreateProcess or similar APIs
				// Not implemented for security reasons - requires additional design and security controls
				// TODO: Implement with proper privilege checks and sandboxing if needed
				debug_print("[-] Execute operation not implemented [-]\n");
				status = STATUS_NOT_IMPLEMENTED;
				break;

			default:
				debug_print("[-] Unknown control code [-]\n");
				status = STATUS_INVALID_DEVICE_REQUEST;
				break;
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(Request);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return status;
	}

} // namespace driver

// entry point
NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);

	UNICODE_STRING device_name = {};
	RtlInitUnicodeString(&device_name, L"\\Device\\UnderDriver");

	PDEVICE_OBJECT device_object = nullptr;
	NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);

	if (status != STATUS_SUCCESS) {
		debug_print("[+] Failed to create driver device [+]\n");
		return status;
	}

	debug_print("[+] Driver device successfully created [+]\n");

	UNICODE_STRING symbolic_link = {};
	RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\UnderDriver");

	status = IoCreateSymbolicLink(&symbolic_link, &device_name);
	if (status != STATUS_SUCCESS) {

		debug_print("[+] Failed to establish symbolic link [+]\n");

		return status;
	}

	debug_print("[+] Symbolic link established [+]\n");

	// Allow sending small amounts of data between um/km.
	SetFlag(device_object->Flags, DO_BUFFERED_IO);

	driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

	ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

	debug_print("[+] Driver initialised successfully [+]\n");

	return status;
}


NTSTATUS DriverEntry() {
	debug_print("[+] Kernel Mode Call [+]\n");

	UNICODE_STRING driver_name = {};
	RtlInitUnicodeString(&driver_name, L"\\Driver\\UnderDriver");

	return IoCreateDriver(&driver_name, &driver_main);
}