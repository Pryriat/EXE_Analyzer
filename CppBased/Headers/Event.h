#pragma once
#include<Windows.h>
#include<string>
#include<iostream>
using std::wcout;
using std::endl;
HANDLE g_ProcessHandle;
HANDLE g_ThreadHandle;
void OnProcessCreated(const CREATE_PROCESS_DEBUG_INFO* pInfo) 
{

	;
}



void OnThreadCreated(const CREATE_THREAD_DEBUG_INFO* pInfo) 
{

	;
}


void OnException(const EXCEPTION_DEBUG_INFO* pInfo)
{
	switch (pInfo->ExceptionRecord.ExceptionCode)
	{
		case EXCEPTION_ACCESS_VIOLATION:
			wcout << "EXCEPTION_ACCESS_VIOLATION at " << pInfo->ExceptionRecord.ExceptionAddress;
			break;
		case EXCEPTION_BREAKPOINT:
			wcout << "Hit BreakPoint at" << pInfo->ExceptionRecord.ExceptionAddress<<endl;
			break;
		default:
			break;
	}
}


void OnProcessExited(const EXIT_PROCESS_DEBUG_INFO* pInfo) {

	;
}



void OnThreadExited(const EXIT_THREAD_DEBUG_INFO* pInfo) 
{

	;
}



void OnOutputDebugString(const OUTPUT_DEBUG_STRING_INFO* pInfo) 
{
	if (pInfo->nDebugStringLength > 0)
	{
		BYTE* pBuffer = (BYTE*)malloc(pInfo->nDebugStringLength);
		if (pBuffer == NULL)
		{
			wcout << "pBuffer Alloc Error!";
			return;
		}
		SIZE_T bytesRead;
		ReadProcessMemory(g_ProcessHandle, pInfo->lpDebugStringData, pBuffer, pInfo->nDebugStringLength, &bytesRead);
		SIZE_T requireLen = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (LPCSTR)pBuffer, pInfo->nDebugStringLength, NULL, 0);
		TCHAR* pWideStr = (TCHAR*)malloc(requireLen * sizeof(TCHAR));
		MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (LPCSTR)pBuffer, pInfo->nDebugStringLength, pWideStr, requireLen);
		std::wcout << TEXT("Debuggee debug string: ") << pWideStr << std::endl;
		free(pWideStr);
		free(pBuffer);
	}
	
}



void OnRipEvent(const RIP_INFO* pInfo) 
{

	;
}



void OnDllLoaded(const LOAD_DLL_DEBUG_INFO* pInfo)
{
	if (pInfo->hFile == INVALID_HANDLE_VALUE)
	{
		wcout << "FileHandleError" << endl;
		return;
	}
	TCHAR* name = new TCHAR[MAX_PATH];
	ZeroMemory(name, 256);
	if (name)
	{
		DWORD ret = GetFinalPathNameByHandle(pInfo->hFile, name, 256, FILE_NAME_NORMALIZED);
		if (ret>0 && ret<MAX_PATH)
		{
			std::wstring c = name;
			if (c.substr(0, 8).compare(TEXT("\\\\?\\UNC\\")) == 0)
			{
				// In case of a network path, replace `\\?\UNC\` with `\\`.
				c = TEXT("\\") + c.substr(7);
			}
			else if (c.substr(0, 4).compare(TEXT("\\\\?\\")) == 0)
			{
				// In case of a local path, crop `\\?\`.
				c = c.substr(4);
			}
			wcout << "LoadDll:" << c << endl;
		}
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
				wcout << "Unknown Error!" << endl;
				break;
			}
	}
	else
		std::wcout << "Alloc Error!";
	delete[] name;
}



void OnDllUnloaded(const UNLOAD_DLL_DEBUG_INFO* pInfo) 
{

	;
}