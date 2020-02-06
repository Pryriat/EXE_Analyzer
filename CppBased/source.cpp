#include <Windows.h>
#include <iostream>
#include <string>
#include"Headers/Event.h"
#include"Headers/Exception.h"

using std::wcout;
using std::endl;



int filter(unsigned int code, struct _EXCEPTION_POINTERS* ep)
{
	if (code == ERROR_INVALID_INDEX)
	{
		wcout << code << "    " << (TCHAR*)ep->ExceptionRecord->ExceptionInformation;
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	return DBG_EXCEPTION_NOT_HANDLED;
}

int wmain(int argc, wchar_t** argv) 
{

	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi = { 0 };

	if (CreateProcess(TEXT("C:\\Users\\hjc98\\Desktop\\win32calc.exe"),NULL,NULL,NULL,FALSE,
		DEBUG_PROCESS | CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi) == FALSE)
	{
		std::wcout << TEXT("CreateProcess failed: ") << GetLastError() << std::endl;
		return -1;
	}

	BOOL waitEvent = TRUE;

	DEBUG_EVENT debugEvent;

	while (waitEvent == TRUE && WaitForDebugEvent(&debugEvent, INFINITE))
	{
		g_ProcessHandle = OpenProcess(DEBUG_PROCESS, false, debugEvent.dwProcessId);
		g_ThreadHandle = OpenThread(DEBUG_PROCESS, false, debugEvent.dwThreadId);
		SuspendThread(g_ThreadHandle);
		switch (debugEvent.dwDebugEventCode) 
		{
			case CREATE_PROCESS_DEBUG_EVENT:
				OnProcessCreated(&debugEvent.u.CreateProcessInfo);
				break;

			case CREATE_THREAD_DEBUG_EVENT:
				OnThreadCreated(&debugEvent.u.CreateThread);
				break;

			case EXCEPTION_DEBUG_EVENT:
				OnException(&debugEvent.u.Exception);
				break;

			case EXIT_PROCESS_DEBUG_EVENT:
				OnProcessExited(&debugEvent.u.ExitProcess);
				waitEvent = FALSE;
				break;

			case EXIT_THREAD_DEBUG_EVENT:
				OnThreadExited(&debugEvent.u.ExitThread);
				waitEvent = false;
				break;

			case LOAD_DLL_DEBUG_EVENT:
				OnDllLoaded(&debugEvent.u.LoadDll);
				break;

			case UNLOAD_DLL_DEBUG_EVENT:
				OnDllUnloaded(&debugEvent.u.UnloadDll);
				break;

			case OUTPUT_DEBUG_STRING_EVENT:
				OnOutputDebugString(&debugEvent.u.DebugString);
				break;

			case RIP_EVENT:
				OnRipEvent(&debugEvent.u.RipInfo);
				break;

			default:
				std::wcout << TEXT("Unknown debug event.") << std::endl;
				break;
		}
		ResumeThread(g_ThreadHandle);
		if (waitEvent == TRUE) 
			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		else 
			break;
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return 0;
}



