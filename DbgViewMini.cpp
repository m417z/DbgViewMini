/*
 * DbgViewMini is based on code from Task Explorer and System Informer:
 * https://github.com/DavidXanatos/TaskExplorer/blob/master/TaskExplorer/API/Windows/Monitors/WinDbgMonitor.cpp
 * https://github.com/processhacker/plugins-extra/blob/master/DbgViewPlugin/log.c
 *
 * Original license:
 *
 * System Informer Plugins -
 *   qt port of Debug View Plugin
 *
 * Copyright (C) 2015-2017 dmex
 * Copyright (C) 2020-2022 David Xanatos
 *
 * This file is part of Task Explorer and contains System Informer code.
 *
 */

#include <Windows.h>
#include <Sddl.h>

#include <stdio.h>

#include <expected>

#define DBG_VIEW_MINI_VERSION "0.1"

#define PAGE_SIZE 0x1000

#define DBWIN_BUFFER_READY L"DBWIN_BUFFER_READY"
#define DBWIN_DATA_READY L"DBWIN_DATA_READY"
#define DBWIN_BUFFER L"DBWIN_BUFFER"

// The Win32 OutputDebugString buffer.
typedef struct _DBWIN_PAGE_BUFFER
{
	ULONG ProcessId; /** The ID of the process. */
	CHAR Buffer[PAGE_SIZE - sizeof(ULONG)]; /** The buffer containing the debug message. */
} DBWIN_PAGE_BUFFER, * PDBWIN_PAGE_BUFFER;

class ERR
{
public:
	ERR(PCSTR name, DWORD code) : name(name), code(code) {}
	PCSTR name;
	DWORD code;
};

struct SWinDbgMonitor
{
	SWinDbgMonitor()
	{
		LocalCaptureEnabled = FALSE;
		LocalBufferReadyEvent = NULL;
		LocalDataReadyEvent = NULL;
		LocalDataBufferHandle = NULL;
		LocalDebugBuffer = NULL;

		GlobalCaptureEnabled = FALSE;
		GlobalBufferReadyEvent = NULL;
		GlobalDataReadyEvent = NULL;
		GlobalDataBufferHandle = NULL;
		GlobalDebugBuffer = NULL;

		KernelCaptureEnabled = FALSE;

		DbgCreateSecurityAttributes();
	}

	~SWinDbgMonitor()
	{
		DbgCleanupSecurityAttributes();
	}

	SECURITY_ATTRIBUTES SecurityAttributes;

	BOOLEAN LocalCaptureEnabled;
	HANDLE LocalBufferReadyEvent;
	HANDLE LocalDataReadyEvent;
	HANDLE LocalDataBufferHandle;
	PDBWIN_PAGE_BUFFER LocalDebugBuffer;

	BOOLEAN GlobalCaptureEnabled;
	HANDLE GlobalBufferReadyEvent;
	HANDLE GlobalDataReadyEvent;
	HANDLE GlobalDataBufferHandle;
	PDBWIN_PAGE_BUFFER GlobalDebugBuffer;

	BOOLEAN KernelCaptureEnabled;

	BOOL DbgCreateSecurityAttributes()
	{
		SecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
		SecurityAttributes.bInheritHandle = FALSE;
		return ConvertStringSecurityDescriptorToSecurityDescriptor(
			L"D:(A;;GRGWGX;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGWGX;;;AN)(A;;GRGWGX;;;RC)(A;;GRGWGX;;;S-1-15-2-1)S:(ML;;NW;;;LW)",
			SDDL_REVISION, &SecurityAttributes.lpSecurityDescriptor, NULL);
	}

	void DbgCleanupSecurityAttributes()
	{
		if (SecurityAttributes.lpSecurityDescriptor)
		{
			LocalFree(SecurityAttributes.lpSecurityDescriptor);
			SecurityAttributes.lpSecurityDescriptor = NULL;
		}
	}

	std::expected<void, ERR> Init(bool bGlobal)
	{
		BOOLEAN& CaptureEnabled = bGlobal ? GlobalCaptureEnabled : LocalCaptureEnabled;
		HANDLE& BufferReadyEvent = bGlobal ? GlobalBufferReadyEvent : LocalBufferReadyEvent;
		HANDLE& DataReadyEvent = bGlobal ? GlobalDataReadyEvent : LocalDataReadyEvent;
		HANDLE& DataBufferHandle = bGlobal ? GlobalDataBufferHandle : LocalDataBufferHandle;
		PDBWIN_PAGE_BUFFER& DebugBuffer = bGlobal ? GlobalDebugBuffer : LocalDebugBuffer;

		SIZE_T viewSize;
		LARGE_INTEGER maximumSize;

		maximumSize.QuadPart = PAGE_SIZE;
		viewSize = sizeof(DBWIN_PAGE_BUFFER);

		if (!(BufferReadyEvent = CreateEvent(&SecurityAttributes, FALSE, FALSE, bGlobal ? L"Global\\" DBWIN_BUFFER_READY : L"Local\\" DBWIN_BUFFER_READY)))
		{
			return std::unexpected(ERR("DBWIN_BUFFER_READY", GetLastError()));
		}

		if (!(DataReadyEvent = CreateEvent(&SecurityAttributes, FALSE, FALSE, bGlobal ? L"Global\\" DBWIN_DATA_READY : L"Local\\" DBWIN_DATA_READY)))
		{
			return std::unexpected(ERR("DBWIN_DATA_READY", GetLastError()));
		}

		if (!(DataBufferHandle = CreateFileMapping(
			INVALID_HANDLE_VALUE,
			&SecurityAttributes,
			PAGE_READWRITE,
			maximumSize.HighPart,
			maximumSize.LowPart,
			bGlobal ? L"Global\\" DBWIN_BUFFER : L"Local\\" DBWIN_BUFFER
		)))
		{
			return std::unexpected(ERR("CreateFileMapping", GetLastError()));
		}

		if (!(DebugBuffer = (PDBWIN_PAGE_BUFFER)MapViewOfFile(
			DataBufferHandle,
			FILE_MAP_READ,
			0,
			0,
			viewSize
		)))
		{
			return std::unexpected(ERR("MapViewOfFile", GetLastError()));
		}

		CaptureEnabled = TRUE;

		return {};
	}

	void UnInit(bool bGlobal)
	{
		BOOLEAN& CaptureEnabled = bGlobal ? GlobalCaptureEnabled : LocalCaptureEnabled;
		HANDLE& BufferReadyEvent = bGlobal ? GlobalBufferReadyEvent : LocalBufferReadyEvent;
		HANDLE& DataReadyEvent = bGlobal ? GlobalDataReadyEvent : LocalDataReadyEvent;
		HANDLE& DataBufferHandle = bGlobal ? GlobalDataBufferHandle : LocalDataBufferHandle;
		PDBWIN_PAGE_BUFFER& DebugBuffer = bGlobal ? GlobalDebugBuffer : LocalDebugBuffer;

		CaptureEnabled = FALSE;

		if (DebugBuffer)
		{
			UnmapViewOfFile(DebugBuffer);
			DebugBuffer = NULL;
		}

		if (DataBufferHandle)
		{
			CloseHandle(DataBufferHandle);
			DataBufferHandle = NULL;
		}

		if (BufferReadyEvent)
		{
			CloseHandle(BufferReadyEvent);
			BufferReadyEvent = NULL;
		}

		if (DataReadyEvent)
		{
			CloseHandle(DataReadyEvent);
			DataReadyEvent = NULL;
		}
	}
};

BOOL GetProcessFileName(DWORD processID, char* buffer, DWORD maxSize)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
	if (!hProcess)
	{
		return FALSE;
	}

	char fullPath[MAX_PATH];
	DWORD size = MAX_PATH;

	if (!QueryFullProcessImageNameA(hProcess, 0, fullPath, &size))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	const char* fileName = strrchr(fullPath, '\\');
	if (fileName)
	{
		fileName++;
	}
	else
	{
		fileName = fullPath;
	}

	strncpy_s(buffer, maxSize, fileName, maxSize - 1);

	CloseHandle(hProcess);
	return TRUE;
}

void StrRemoveNewlines(char* src, char* dst)
{
	char* lastNewlineSequence = nullptr;

	while (*src)
	{
		if (*src == '\r' || *src == '\n')
		{
			if (!lastNewlineSequence)
			{
				lastNewlineSequence = dst;
			}

			*dst++ = ' ';

			if (src[0] == '\r' && src[1] == '\n')
			{
				src += 2;
			}
			else
			{
				src++;
			}
		}
		else
		{
			*dst++ = *src++;
			lastNewlineSequence = nullptr;
		}
	}

	if (lastNewlineSequence)
	{
		*lastNewlineSequence = '\0';
	}
	else
	{
		*dst = '\0';
	}
}

DWORD DbgEventsThread(bool bGlobal, SWinDbgMonitor* m)
{
	HANDLE& BufferReadyEvent = bGlobal ? m->GlobalBufferReadyEvent : m->LocalBufferReadyEvent;
	HANDLE& DataReadyEvent = bGlobal ? m->GlobalDataReadyEvent : m->LocalDataReadyEvent;
	PDBWIN_PAGE_BUFFER debugMessageBuffer = bGlobal ? m->GlobalDebugBuffer : m->LocalDebugBuffer;

	DWORD lastProcessId = 0;
	char lastProcessFileName[MAX_PATH];

	while (TRUE)
	{
		SetEvent(BufferReadyEvent);

		DWORD status = WaitForSingleObject(DataReadyEvent, INFINITE);
		if (status != WAIT_OBJECT_0)
			break;

		SYSTEMTIME st;
		GetLocalTime(&st);

		if (debugMessageBuffer->ProcessId != lastProcessId)
		{
			lastProcessId = debugMessageBuffer->ProcessId;
			if (!GetProcessFileName(debugMessageBuffer->ProcessId, lastProcessFileName, MAX_PATH)) {
				strcpy_s(lastProcessFileName, "<unknown>");
			}
		}

		char bufferWithoutNewlines[sizeof(debugMessageBuffer->Buffer)];
		StrRemoveNewlines(debugMessageBuffer->Buffer, bufferWithoutNewlines);

		printf("%02d:%02d:%02d.%03d %d %s  %s\n",
			st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
			debugMessageBuffer->ProcessId,
			lastProcessFileName,
			bufferWithoutNewlines);
	}

	return 0;
}

DWORD WINAPI DbgEventsLocalThread(PVOID Parameter)
{
	return DbgEventsThread(false, (SWinDbgMonitor*)Parameter);
}

DWORD WINAPI DbgEventsGlobalThread(PVOID Parameter)
{
	return DbgEventsThread(true, (SWinDbgMonitor*)Parameter);
}

int main()
{
	printf("DebugViewMini v%s\n", DBG_VIEW_MINI_VERSION);
	printf("Listening for OutputDebugString messages...\n");

	auto monitor = new SWinDbgMonitor;

	if (auto status = monitor->Init(false); !status.has_value())
	{
		monitor->UnInit(false);
		printf("Local capture error: %s (%u)\n", status.error().name, status.error().code);
	}

	if (HANDLE threadHandle = CreateThread(nullptr, 0, DbgEventsLocalThread, monitor, 0, nullptr))
	{
		CloseHandle(threadHandle);
	}

	if (auto status = monitor->Init(true); !status.has_value())
	{
		monitor->UnInit(true);
		if (status.error().code != ERROR_ACCESS_DENIED)
		{
			printf("Global capture error: %s (%u)\n", status.error().name, status.error().code);
		}
	}

	if (HANDLE threadHandle = CreateThread(nullptr, 0, DbgEventsGlobalThread, monitor, 0, nullptr))
	{
		CloseHandle(threadHandle);
	}

	// Continue logging in the newly created threads.
	ExitThread(0);

	/*
	getchar();

	printf("Shutting down...\n");

	if (monitor->LocalCaptureEnabled)
		monitor->UnInit(false);
	if (monitor->GlobalCaptureEnabled)
		monitor->UnInit(true);

	delete monitor;

	return 0;
	*/
}
