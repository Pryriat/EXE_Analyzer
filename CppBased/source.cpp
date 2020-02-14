
#include <Windows.h>
#include <iostream>
#include <string>
#include<easyhook.h>
#include"Headers/Event.h"
#include"Headers/Exception.h"
#include"MyProcessApi.h"

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

void output(std::wstring in)
{
	std::wcout << in << endl;
}

int wmain(int argc, wchar_t** argv) 
{
	WCHAR* dllToInject = const_cast<WCHAR*>(L".\\x64\\Debug\\hook.dll");
	WCHAR* dllToInject32 = const_cast<WCHAR*>(L".\\Debug\\hook.dll");
	//WCHAR* dllToInject32 = const_cast<WCHAR*>(L"C:\\Users\\hjc\\Desktop\\hook.dll");

	std::wcout << argv[1];
	std::wcout << dllToInject32;
	std::cin.get();
	ULONG proc;
	NTSTATUS nt = RhCreateAndInject(argv[1], const_cast<WCHAR*>(L""), CREATE_NEW_CONSOLE, EASYHOOK_INJECT_DEFAULT, dllToInject32, dllToInject, NULL, 0, &proc);
	//NTSTATUS nt = RhCreateAndInject(const_cast<WCHAR*>(L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"), const_cast<WCHAR*>(L""), CREATE_NEW_CONSOLE, EASYHOOK_INJECT_DEFAULT, dllToInject32, dllToInject, NULL, 0, &proc);
	//NTSTATUS nt = RhCreateAndInject(const_cast<WCHAR*>(L"D:\\Program Files\\Typora\\Typora.exe"), const_cast<WCHAR*>(L""), CREATE_NEW_CONSOLE, EASYHOOK_INJECT_DEFAULT, dllToInject32, dllToInject, NULL, 0, &proc);
	if (nt != 0)
	{
		printf("RhInjectLibrary failed with error code = %d\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		std::wcout << err << "\n";
	}
	else
	{
		std::wcout << L"Library injected successfully.\n";
	}
	std::wcout << "Press Enter to exit";
	std::wstring input;
	std::getline(std::wcin, input);
	std::getline(std::wcin, input);
	return 0;
	/*
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi = { 0 };

	if (CreateProcess(TEXT("D:\\Program Files\\Typora\\Typora.exe"),NULL,NULL,NULL,FALSE,
		DEBUG_PROCESS | CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi) == FALSE)
	{
		std::wcout << TEXT("CreateProcess failed: ") << GetLastError() << std::endl;
		return -1;
	}
	WCHAR* dllToInject = const_cast<WCHAR*>(L".\\hook.dll");
	WCHAR* dllToInject32 = const_cast<WCHAR*>(L".\\Debug\\hook.dll");
	BOOL waitEvent = TRUE;

	DEBUG_EVENT debugEvent;
	
	//SuspendThread(g_ThreadHandle);
	// Inject dllToInject into the target process Id, passing 
	// freqOffset as the pass through data.
	NTSTATUS nt = RhInjectLibrary(
		pi.dwProcessId ,   // The process to inject into
		0,           // ThreadId to wake up upon injection
		EASYHOOK_INJECT_DEFAULT,
		dllToInject32, // 32-bit
		dllToInject,		 // 64-bit not provided
		NULL, // data to send to injected DLL entry point
		0// size of data to send
	);
	if (nt != 0)
	{
		printf("RhInjectLibrary failed with error code = %d\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		std::wcout << err << "\n";
		std::cin.get();
	}
	else
	{
		std::wcout << L"Library injected successfully.\n";
	}

	while (waitEvent == TRUE && WaitForDebugEvent(&debugEvent, INFINITE))
	{
		g_ProcessHandle = OpenProcess(DEBUG_PROCESS, false, debugEvent.dwProcessId);
		g_ThreadHandle = OpenThread(DEBUG_PROCESS, false, debugEvent.dwThreadId);
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
				//waitEvent = FALSE;
				break;

			case EXIT_THREAD_DEBUG_EVENT:
				OnThreadExited(&debugEvent.u.ExitThread);
				//waitEvent = false;
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
		//ResumeThread(g_ThreadHandle);
		if (waitEvent == TRUE) 
			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		else 
			break;
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return 0;
	*/
}

