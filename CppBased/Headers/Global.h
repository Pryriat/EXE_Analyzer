#pragma once

#include<string>
#include<vector>
#include<map>
#include<easyhook.h>
#include<codecvt>
#include<locale>
#include<Psapi.h>
#include<wininet.h>
#include<fileapi.h>
#include<synchapi.h>
#include<plog/Log.h>
#include<plog/Record.h>
#pragma  comment(lib,"Wininet.lib")
#pragma  comment(lib,"Psapi.lib")
#define MAX_PATH 260

std::string cn = "None";
std::wstring wn = L"None";
std::wstring inline GetLastErrorAsString(DWORD ErrorCode)
{
	WCHAR* text;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&text, 0, NULL);
	std::wstring result(text);    //½á¹û
	LocalFree(text);
	return result;
}

std::wstring inline GetFileNameByFileHandle(HANDLE hFile)
{
	if (hFile == NULL)
		return L"None";
	TCHAR* name = new TCHAR[MAX_PATH];
	ZeroMemory(name, 256);
	if (name)
	{
		DWORD ret = GetFinalPathNameByHandle(hFile, name, 256, FILE_NAME_NORMALIZED);
		if (ret > 0 && ret < MAX_PATH)
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
			delete[] name;
			return c;
		}
		else
		{
			delete[] name;
			return std::wstring(L"FileNameError");
		}
	}
	return std::wstring(L"AllocError");
}

std::wstring inline GetProcessNameByHandle(HANDLE hProc)
{
	TCHAR* buffer = new TCHAR[260];
	DWORD tmp = 260;
	DWORD rtn = QueryFullProcessImageNameW(hProc,0, buffer, &tmp);
	if (rtn)
	{
		std::wstring c = buffer;
		delete[] buffer;
		return c;
	}
	else
		return std::wstring();
	/*
	std::wstring c(L"GetProcNameError!Handle:");
	c += std::to_wstring(reinterpret_cast<ULONG>(hProc));
	c += L"  , Reason:";
	c += GetLastErrorAsString(::GetLastError());
	return c;
	*/
}

void inline Check(const std::string& API, const NTSTATUS& result)
{
	if (FAILED(result))
	{
		PLOGE << "Hook " << API << "Error:" << RtlGetLastErrorString() << std::endl;
	}
}

inline LPCSTR sc(LPCSTR in)
{
	if (in == NULL)
		return cn.c_str();
	return in;
}

inline LPCWSTR sc(LPCWSTR in)
{
	if (in == NULL)
		return wn.c_str();
	return in;
}
