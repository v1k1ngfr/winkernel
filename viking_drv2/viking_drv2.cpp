#include <ntifs.h>
#include <ntddk.h>
#include <..\..\viking_drv2.h>

void getOSversion() {
	//variables
	OSVERSIONINFOEXW osVersionInfo;
	NTSTATUS status = STATUS_SUCCESS;
	osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	status = RtlGetVersion((POSVERSIONINFOW)&osVersionInfo);
	NT_ASSERT(NT_SUCCESS(status));
	/*
	typedef struct _OSVERSIONINFOEXW {
	   ULONG  dwOSVersionInfoSize;
	   ULONG  dwMajorVersion;
	   ULONG  dwMinorVersion;
	   ULONG  dwBuildNumber;
	   ULONG  dwPlatformId;
	   WCHAR  szCSDVersion[128];
	  USHORT wServicePackMajor;
	  USHORT wServicePackMinor;
	  USHORT wSuiteMask;
	  UCHAR  wProductType;
	  UCHAR  wReserved;
	}
	*/
	KdPrint(("[VIKING][VERSION] Major   : %u\n", osVersionInfo.dwMajorVersion));
	KdPrint(("[VIKING][VERSION] Minor   : %u\n", osVersionInfo.dwMinorVersion));
	KdPrint(("[VIKING][VERSION] Build   : %u\n", osVersionInfo.dwBuildNumber));
	KdPrint(("[VIKING][VERSION] OS version Info Size   : %u\n", osVersionInfo.dwOSVersionInfoSize));
	KdPrint(("[VIKING][VERSION] Platform ID   : %u\n", osVersionInfo.dwPlatformId));
	KdPrint(("[VIKING][VERSION] CSD Version (SP Level)  : %s\n", osVersionInfo.szCSDVersion));
	KdPrint(("[VIKING][VERSION] wServicePackMajor  : %u\n", osVersionInfo.wServicePackMajor));
	KdPrint(("[VIKING][VERSION] wServicePackMinor  : %u\n", osVersionInfo.wServicePackMinor));
	KdPrint(("[VIKING][VERSION] wSuiteMask  : %u\n", osVersionInfo.wSuiteMask));
	KdPrint(("[VIKING][VERSION] wProductType  : %s\n", osVersionInfo.wProductType));
	KdPrint(("[VIKING][VERSION] wReserved  : %s\n", osVersionInfo.wReserved));

}

// Create / close major functions in the same routine
_Use_decl_annotations_
NTSTATUS vikingdrv2CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp){
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT); // propagate the IRP to I/O manager and notify the client the operation completed
	return STATUS_SUCCESS;
}

// if DriverEntry completed successfully, then undo whatever was done
void vikingdrv2Unload(_In_ PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\vikingdrv2");
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);
	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);
	KdPrint(("[VIKING] driver Unload called\n"));
}
// 
_Use_decl_annotations_
NTSTATUS vikingdrv2DeviceControl(PDEVICE_OBJECT, PIRP Irp) {
	// get our IO_STACK_LOCATION
	auto stack = IoGetCurrentIrpStackLocation(Irp); // IO_STACK_LOCATION*
	auto status = STATUS_SUCCESS;
	// in the structure stack->Parameters.DeviceIoControl we find information conveyed by the client
	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_PRIORITY_BOOSTER_SET_PRIORITY: {
		// do the work
		auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (len < sizeof(ThreadData)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		// process the buffer but if null pointer we abort
		auto data = (ThreadData*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
		if (data == nullptr) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		// check if the priority is in a legal range
		if (data->Priority < 1 || data->Priority > 31) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		// function thats look up a thread by its ID. Turn our thread ID to a pointer
		PETHREAD Thread;
		status = PsLookupThreadByThreadId(ULongToHandle(data->ThreadId), &Thread);
		if (!NT_SUCCESS(status))
			break;
		// set the new priority
		KeSetPriorityThread((PKTHREAD)Thread, data->Priority);
		ObDereferenceObject(Thread);
		KdPrint(("Thread Priority change for %d to %d succeeded!\n",
			data->ThreadId, data->Priority));
		break;
	}
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	// send a completion response to the client
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

// main
extern "C"
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	// variables
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\vikingdrv2"); // internal device name
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\vikingdrv2"); // symlink

	PDEVICE_OBJECT DeviceObject;
	// code
	DriverObject->DriverUnload = vikingdrv2Unload;
	KdPrint(("[VIKING]  driver initialized successfully\n"));
	getOSversion();

	// Set up the dispatch routine
	DriverObject->MajorFunction[IRP_MJ_CREATE] = vikingdrv2CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = vikingdrv2CreateClose;

	// Initialization of the dispatch routine
	/*
	BOOL WINAPI DeviceIoControl(
		_In_ HANDLE hDevice,
		_In_ DWORD dwIoControlCode,
		_In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
		_In_ DWORD nInBufferSize,
		_Out_writes_bytes_to_opt_(nOutBufferSize,*lpBytesReturned) LPVOID lpOutBuffer,
		_In_ DWORD nOutBufferSize,
		_Out_opt_ LPDWORD lpBytesReturned,
		_Inout_opt_ LPOVERLAPPED lpOverlapped
	);
	There are three important pieces to DeviceIoControl :
		A control code
		An input buffer
		An output buffer
	*/
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = vikingdrv2DeviceControl;

	//create the device object so that the client can reach the driver and open handles
	NTSTATUS status = IoCreateDevice(
		DriverObject,		// our driver object,
		0,					// no need for extra bytes,
		& devName,			// the device name,
		FILE_DEVICE_UNKNOWN,	// device type,
		0,					// characteristics flags,
		FALSE,				// not exclusive,
		& DeviceObject		// the resulting pointer
	);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create device object (0x%08X)\n", status));
		return status;
	}

	// now we have a pointer to our device object, 
	// make it accessible to user mode callers by providing symbolic link
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create symbolic link (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	return STATUS_SUCCESS;
}