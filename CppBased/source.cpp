#include <Windows.h>
#include <iostream>
#include <string>
#include"Exception.h"
using std::wcout;
using std::endl;



void OnProcessCreated(const CREATE_PROCESS_DEBUG_INFO*);
void OnThreadCreated(const CREATE_THREAD_DEBUG_INFO*);
void OnProcessExited(const EXIT_PROCESS_DEBUG_INFO*);
void OnThreadExited(const EXIT_THREAD_DEBUG_INFO*);
void OnOutputDebugString(const OUTPUT_DEBUG_STRING_INFO*);
void OnRipEvent(const RIP_INFO*);
void OnDllLoaded(const LOAD_DLL_DEBUG_INFO*);
void OnDllUnloaded(const UNLOAD_DLL_DEBUG_INFO*);



int filter(unsigned int code, struct _EXCEPTION_POINTERS* ep)
{
	if (code == ERROR_INVALID_INDEX)
	{
		wcout << code << "    " << (TCHAR*)ep->ExceptionRecord->ExceptionInformation;
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	return DBG_EXCEPTION_NOT_HANDLED;
}

int wmain(int argc, wchar_t** argv) {

	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi = { 0 };

	if (CreateProcess(
		TEXT("C:\\Program Files (x86)\\NetSarang\\Xshell 6\\Xshell.exe"),
		NULL,
		NULL,
		NULL,
		FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi) == FALSE) {

		std::wcout << TEXT("CreateProcess failed: ") << GetLastError() << std::endl;
		return -1;
	}

	BOOL waitEvent = TRUE;

	DEBUG_EVENT debugEvent;

	while (waitEvent == TRUE && WaitForDebugEvent(&debugEvent, INFINITE)) {

		switch (debugEvent.dwDebugEventCode) {

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

		if (waitEvent == TRUE) {
			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		}
		else {
			break;
		}
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return 0;
}



void OnProcessCreated(const CREATE_PROCESS_DEBUG_INFO* pInfo) {

	std::wcout << TEXT("Debuggee was created.") << std::endl;
}



void OnThreadCreated(const CREATE_THREAD_DEBUG_INFO* pInfo) {

	std::wcout << TEXT("A new thread was created.") << std::endl;
}




void OnProcessExited(const EXIT_PROCESS_DEBUG_INFO* pInfo) {

	std::wcout << TEXT("Debuggee was terminated.") << std::endl;
}



void OnThreadExited(const EXIT_THREAD_DEBUG_INFO* pInfo) {

	std::wcout << TEXT("A thread was terminated.") << std::endl;
}



void OnOutputDebugString(const OUTPUT_DEBUG_STRING_INFO* pInfo) {

	std::wcout << TEXT("Debuggee outputed debug string.") << std::endl;
}



void OnRipEvent(const RIP_INFO* pInfo) {

	std::wcout << TEXT("A RIP_EVENT occured.") << std::endl;
}



void OnDllLoaded(const LOAD_DLL_DEBUG_INFO* pInfo) 
{
	if (pInfo->hFile == INVALID_HANDLE_VALUE)
	{
		wcout << "FileHandleError" << endl;
		return;
	}
	TCHAR* name = new TCHAR[256];
	ZeroMemory(name, 256);
	if (name)
	{
		if (GetFinalPathNameByHandle(pInfo->hFile, name, 256, FILE_NAME_NORMALIZED) > 0)
			std::wcout << name << std::endl;
		else
			switch (GetLastError())
			{
			case ERROR_PATH_NOT_FOUND:
				wcout << "ERROR_PATH_NOT_FOUND" << endl;
				break;
			case ERROR_NOT_ENOUGH_MEMORY:
				wcout << "ERROR_NOT_ENOUGH_MEMORY" << endl;
				break;
			case ERROR_INVALID_PARAMETER:
				wcout << "ERROR_INVALID_PARAMETER" << endl;
				break;
			default:
				wcout << "Unknown" << endl;
				break;
			}
	}
	else
		std::wcout << "Error!";
	delete[] name;
}



void OnDllUnloaded(const UNLOAD_DLL_DEBUG_INFO* pInfo) {

	std::wcout << TEXT("A dll was unloaded.") << std::endl;
}