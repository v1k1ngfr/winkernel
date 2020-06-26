#include <windows.h>
#include <stdio.h>
#include "..\viking_drv2\viking_drv2.h"

int Error(const char* message) {
	printf("%s (error=%d)\n", message, GetLastError());
	return 1;
}

int main(int argc, const char* argv[]) {
	if (argc < 3) {
		printf("Usage: Booster <threadid> <priority>\n");
		return 0;
	}

	//open an handle to the device, using the symlink
	HANDLE hDevice = CreateFile(L"\\\\.\\vikingdrv2", GENERIC_WRITE,
		FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hDevice == INVALID_HANDLE_VALUE)
		return Error("Failed to open device");

	ThreadData data;
	data.ThreadId = atoi(argv[1]);	// command line first argument
	data.Priority = atoi(argv[2]);	// command line second argument

	// Now we’re ready to call DeviceIoControl and close the device handle afterwards
	// DeviceIoControl reaches the driver by invoking the IRP_MJ_DEVICE_CONTROL major function
	DWORD returned;
	BOOL success = DeviceIoControl(hDevice,
		IOCTL_PRIORITY_BOOSTER_SET_PRIORITY,// control code
		&data, sizeof(data),				// input buffer and length
		nullptr, 0,							// output buffer and length
		&returned, nullptr);
	if (success)
		printf("Priority change succeeded!\n");
	else
		Error("Priority change failed!");

	CloseHandle(hDevice);
}