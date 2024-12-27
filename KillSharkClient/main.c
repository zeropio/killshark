#include <Windows.h>
#include <stdio.h>

#define DEVICE_NAME		L"\\Device\\KillShark"
#define SYMLINK_NAME	L"\\??\\KillShark"

#define IOCTL_FILTER_PROCESS_BUFFER		0x170038 

struct Connection
{
	UINT32 SourceTargetIp;
	unsigned short SourcePort;
	UINT32 DestinationTargetIp;
	unsigned short DestinationPort;
};

int main()
{
	HANDLE hDevice;
	DWORD bytesReturned;
	NTSTATUS status;

	// Start buffer
	struct Connection buffer;
	buffer.SourceTargetIp = (172U << 24) | (16U << 16) | (0U << 8) | 138U; // "172.16.0.138"
	buffer.SourcePort = 8000;
	buffer.DestinationTargetIp = (172U << 24) | (16U << 16) | (0U << 8) | 142U; // "172.16.0.142"
	buffer.DestinationPort = 11111;

	// Open handle
	hDevice = CreateFile(
		SYMLINK_NAME,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Bad handle!!!!\n");
		printf("Failed: %lu\n", GetLastError());
		return 1;
	}

	printf("GOOD HANDLE!!!!!!!\n");

	printf("Source IP: %u.%u.%u.%u\n",
		(buffer.SourceTargetIp >> 24) & 0xFF,
		(buffer.SourceTargetIp >> 16) & 0xFF,
		(buffer.SourceTargetIp >> 8) & 0xFF,
		buffer.SourceTargetIp & 0xFF
		);
	printf("Source Port: %u\n", buffer.SourcePort);
	printf("Source IP: %u.%u.%u.%u\n",
		(buffer.DestinationTargetIp >> 24) & 0xFF,
		(buffer.DestinationTargetIp >> 16) & 0xFF,
		(buffer.DestinationTargetIp >> 8) & 0xFF,
		buffer.DestinationTargetIp & 0xFF
		);
	printf("Source Port: %u\n", buffer.DestinationPort);

	// Open IOCTL
	status = DeviceIoControl(
		hDevice,
		IOCTL_FILTER_PROCESS_BUFFER,
		&buffer,
		sizeof(buffer),
		NULL,
		0,
		&bytesReturned,
		NULL
		);

	if (!status)
		printf("DeviceIoControl failed: %d\n", GetLastError());
	else
		printf("NOICE!!!!!\n");

	CloseHandle(hDevice);
	return 0;
}
