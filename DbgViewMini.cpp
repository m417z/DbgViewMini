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
#include <tlhelp32.h>

#include <stdio.h>

#include <expected>
#include <optional>
#include <string>
#include <unordered_map>

#define DBG_VIEW_MINI_VERSION "1.0.2"

#define PAGE_SIZE 0x1000

#define DBWIN_BUFFER_READY "DBWIN_BUFFER_READY"
#define DBWIN_DATA_READY "DBWIN_DATA_READY"
#define DBWIN_BUFFER "DBWIN_BUFFER"

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
	SWinDbgMonitor(const char* pattern = nullptr) : Pattern(pattern)
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

	const char* Pattern;

	BOOL DbgCreateSecurityAttributes()
	{
		SecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
		SecurityAttributes.bInheritHandle = FALSE;
		return ConvertStringSecurityDescriptorToSecurityDescriptor(
			"D:(A;;GRGWGX;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGWGX;;;AN)(A;;GRGWGX;;;RC)(A;;GRGWGX;;;S-1-15-2-1)S:(ML;;NW;;;LW)",
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

		if (!(BufferReadyEvent = CreateEvent(&SecurityAttributes, FALSE, FALSE, bGlobal ? "Global\\" DBWIN_BUFFER_READY : "Local\\" DBWIN_BUFFER_READY)) ||
			GetLastError() == ERROR_ALREADY_EXISTS)
		{
			return std::unexpected(ERR("DBWIN_BUFFER_READY", GetLastError()));
		}

		if (!(DataReadyEvent = CreateEvent(&SecurityAttributes, FALSE, FALSE, bGlobal ? "Global\\" DBWIN_DATA_READY : "Local\\" DBWIN_DATA_READY)) ||
			GetLastError() == ERROR_ALREADY_EXISTS)
		{
			return std::unexpected(ERR("DBWIN_DATA_READY", GetLastError()));
		}

		if (!(DataBufferHandle = CreateFileMapping(
			INVALID_HANDLE_VALUE,
			&SecurityAttributes,
			PAGE_READWRITE,
			maximumSize.HighPart,
			maximumSize.LowPart,
			bGlobal ? "Global\\" DBWIN_BUFFER : "Local\\" DBWIN_BUFFER
		)) || GetLastError() == ERROR_ALREADY_EXISTS)
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

// https://github.com/tidwall/match.c
//
// match returns true if str matches pattern. This is a very
// simple wildcard match where '*' matches on any number characters
// and '?' matches on any one character.
//
// pattern:
//   { term }
// term:
// 	 '*'         matches any sequence of non-Separator characters
// 	 '?'         matches any single non-Separator character
// 	 c           matches character c (c != '*', '?')
// 	'\\' c       matches character c
bool match(const char* pat, size_t plen, const char* str, size_t slen)
{
	while (plen > 0)
	{
		if (pat[0] == '\\')
		{
			if (plen == 1) return false;
			pat++; plen--;
		}
		else if (pat[0] == '*')
		{
			if (plen == 1) return true;
			if (pat[1] == '*')
			{
				pat++; plen--;
				continue;
			}
			if (match(pat + 1, plen - 1, str, slen)) return true;
			if (slen == 0) return false;
			str++; slen--;
			continue;
		}
		if (slen == 0) return false;
		if (pat[0] != '?' && str[0] != pat[0]) return false;
		pat++; plen--;
		str++; slen--;
	}
	return slen == 0 && plen == 0;
}

std::unordered_map<DWORD, std::string> GetProcessNames()
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return {};
	}

	std::unordered_map<DWORD, std::string> result;

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32))
	{
		do
		{
			result.try_emplace(pe32.th32ProcessID, pe32.szExeFile);
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return result;
}

size_t StrRemoveNewlines(const char* src, char* dst)
{
	char* start = dst;
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

	char* end = lastNewlineSequence ? lastNewlineSequence : dst;
	*end = '\0';
	return end - start;
}

DWORD DbgEventsThread(bool bGlobal, SWinDbgMonitor* m)
{
	HANDLE& BufferReadyEvent = bGlobal ? m->GlobalBufferReadyEvent : m->LocalBufferReadyEvent;
	HANDLE& DataReadyEvent = bGlobal ? m->GlobalDataReadyEvent : m->LocalDataReadyEvent;
	PDBWIN_PAGE_BUFFER debugMessageBuffer = bGlobal ? m->GlobalDebugBuffer : m->LocalDebugBuffer;

	const char* pattern = m->Pattern;
	size_t patternLen = pattern ? strlen(pattern) : 0;

	std::unordered_map<DWORD, std::string> processNames;
	DWORD processNamesTickCount = 0;

	while (TRUE)
	{
		SetEvent(BufferReadyEvent);

		DWORD status = WaitForSingleObject(DataReadyEvent, INFINITE);
		if (status != WAIT_OBJECT_0)
			break;

		char bufferWithoutNewlines[sizeof(debugMessageBuffer->Buffer)];
		size_t bufferWithoutNewlinesLen = StrRemoveNewlines(debugMessageBuffer->Buffer, bufferWithoutNewlines);

		if (pattern && !match(pattern, patternLen, bufferWithoutNewlines, bufferWithoutNewlinesLen))
			continue;

		SYSTEMTIME st;
		GetLocalTime(&st);

		if (GetTickCount() - processNamesTickCount > 1000 * 60)
		{
			processNames.clear();
		}

		const char* processName;
		if (auto it = processNames.find(debugMessageBuffer->ProcessId); it != processNames.end())
		{
			processName = it->second.c_str();
		}
		else
		{
			processNames = GetProcessNames();
			processNamesTickCount = GetTickCount();

			if (auto it = processNames.find(debugMessageBuffer->ProcessId); it != processNames.end())
			{
				processName = it->second.c_str();
			}
			else
			{
				processName = "<unknown>";
			}
		}

		printf("%02d:%02d:%02d.%03d %d %s  %s\n",
			st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
			debugMessageBuffer->ProcessId,
			processName,
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

void PrintBanner()
{
	printf("DbgViewMini v%s\n", DBG_VIEW_MINI_VERSION);
}

int main(int argc, char* argv[])
{
	bool local = false;
	bool global = false;
	const char* pattern = nullptr;

	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--local") == 0)
		{
			local = true;
		}
		else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--global") == 0)
		{
			global = true;
		}
		else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pattern") == 0)
		{
			if (i + 1 < argc)
			{
				pattern = argv[i + 1];
				i++;
			}
			else
			{
				PrintBanner();
				printf("Missing pattern\n");
				return 1;
			}
		}
		else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--no-buffering") == 0)
		{
			setvbuf(stdout, nullptr, _IONBF, 0);
			setvbuf(stderr, nullptr, _IONBF, 0);
		}
		else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
		{
			PrintBanner();
			printf("Usage: DbgViewMini.exe [-l|--local] [-g|--global] [-p|--pattern <pattern>] [-n|--no-buffering]\n");
			return 0;
		}
		else
		{
			PrintBanner();
			printf("Unknown option: %s\n", argv[i]);
			return 1;
		}
	}

	if (!local && !global)
	{
		local = true;
		global = true;
	}

	PrintBanner();
	printf("Listening for OutputDebugString messages...\n");

	static SWinDbgMonitor monitor(pattern);

	if (local)
	{
		std::optional<ERR> error;
		if (auto status = monitor.Init(false); !status.has_value())
		{
			error = status.error();
		}
		else if (HANDLE threadHandle = CreateThread(nullptr, 0, DbgEventsLocalThread, &monitor, 0, nullptr); !threadHandle)
		{
			error = ERR("CreateThread", GetLastError());
		}
		else
		{
			CloseHandle(threadHandle);
		}

		if (error)
		{
			monitor.UnInit(false);
			printf("Local capture error: %s (%u)\n", error->name, error->code);
			printf("Another DbgViewMini instance (or a similar application) might be running.\n");
		}
	}

	if (global)
	{
		std::optional<ERR> error;
		if (auto status = monitor.Init(true); !status.has_value())
		{
			error = status.error();
		}
		else if (HANDLE threadHandle = CreateThread(nullptr, 0, DbgEventsGlobalThread, &monitor, 0, nullptr); !threadHandle)
		{
			error = ERR("CreateThread", GetLastError());
		}
		else
		{
			CloseHandle(threadHandle);
		}

		if (error)
		{
			monitor.UnInit(true);
			if (error->code != ERROR_ACCESS_DENIED || !local)
			{
				printf("Global capture error: %s (%u)\n", error->name, error->code);
			}
		}
	}

	if (!monitor.LocalCaptureEnabled && !monitor.GlobalCaptureEnabled)
	{
		return 1;
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
