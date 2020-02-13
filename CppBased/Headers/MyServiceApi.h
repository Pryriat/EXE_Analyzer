#pragma once
#include"Global.h"
#include <functional> 
using std::map;
using std::endl;
using std::wstring;

class MyServiceApi
{
public:
	static map<SC_HANDLE, wstring>ServiceMap;
	static map<std::string, BOOL>ServiceSwitch;
	static USHORT Level;
};

BOOL WINAPI MyCloseServiceHandle(SC_HANDLE hSCObject);
SC_HANDLE WINAPI MyOpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
SC_HANDLE WINAPI MyOpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
SC_HANDLE WINAPI MyOpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess);
SC_HANDLE WINAPI MyOpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);
BOOL WINAPI MyChangeServiceConfig2A(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo);
void PreCheck(const std::string& in, NTSTATUS Result);

HOOK_TRACE_INFO CloseServiceHandleHook;
HOOK_TRACE_INFO OpenSCManagerAHook;
HOOK_TRACE_INFO OpenSCManagerWHook;
HOOK_TRACE_INFO OpenServiceAHook;
HOOK_TRACE_INFO OpenServiceWHook;

map<SC_HANDLE, wstring> MyServiceApi::ServiceMap;
map<std::string, BOOL> MyServiceApi::ServiceSwitch;
USHORT MyServiceApi::Level;

void MyServiceApiInit()
{
	PreCheck("CloseServiceHandle", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CloseServiceHandle"), MyCloseServiceHandle, NULL, &CloseServiceHandleHook));
	PreCheck("OpenSCManagerA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "OpenSCManagerA"), MyOpenSCManagerA, NULL, &OpenSCManagerAHook));
	PreCheck("OpenSCManagerW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "OpenSCManagerW"), MyOpenSCManagerW, NULL, &OpenSCManagerWHook));
	PreCheck("OpenServiceA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "OpenServiceA"), MyOpenServiceA, NULL, &OpenServiceAHook));
	PreCheck("OpenServiceW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "OpenServiceW"), MyOpenServiceW, NULL, &OpenServiceWHook));

	ULONG ACLEntries[1] = { 0 };

	::Check("CloseServiceHandle", LhSetExclusiveACL(ACLEntries, 1, &CloseServiceHandleHook));
	::Check("OpenSCManagerA", LhSetExclusiveACL(ACLEntries, 1, &OpenSCManagerAHook));
	::Check("OpenSCManagerW", LhSetExclusiveACL(ACLEntries, 1, &OpenSCManagerWHook));
	::Check("OpenServiceA", LhSetExclusiveACL(ACLEntries, 1, &OpenServiceAHook));
	::Check("OpenServiceW", LhSetExclusiveACL(ACLEntries, 1, &OpenServiceWHook));
}

void PreCheck(const std::string& in, NTSTATUS Result)
{
	if (FAILED(Result))
		PLOGE << "Hook " << in << " Error:" << RtlGetLastErrorString() << std::endl;
	else
		MyServiceApi::ServiceSwitch[in] = true;
}

BOOL WINAPI MyCloseServiceHandle(SC_HANDLE hSCObject)
{
	BOOL rtn = CloseServiceHandle(hSCObject);
	if (rtn)
		MyServiceApi::ServiceMap.erase(hSCObject);
	PLOGD << "CloseServiceHandle->Handle:" << reinterpret_cast<ULONG>(hSCObject) << endl;
	return rtn;
}

SC_HANDLE WINAPI MyOpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess)
{
	wstring MN = (lpMachineName == NULL ?  L"LocalMachine" : std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpMachineName));
	wstring DN = (lpDatabaseName == NULL ? L"SERVICES_ACTIVE_DATABASE" : std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpDatabaseName));
	PLOGD << "OpenSCManagerA->MachineName:" << MN
		<<"  ,DatabaseName:" << DN << endl;
	SC_HANDLE rtn = OpenSCManagerA(lpMachineName, lpDatabaseName, dwDesiredAccess);
	if (rtn != NULL)
		MyServiceApi::ServiceMap[rtn] = MN + L'\\' + DN + L'\\';
	return rtn;
}

SC_HANDLE WINAPI MyOpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess)
{
	wstring MN = (lpMachineName == NULL ? L"LocalMachine" : lpMachineName);
	wstring DN = (lpDatabaseName == NULL ? L"SERVICES_ACTIVE_DATABASE" : lpDatabaseName);
	PLOGD << "OpenSCManagerA->MachineName:" << MN
		<< "  ,DatabaseName:" << DN << endl;
	SC_HANDLE rtn = OpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess);
	if (rtn != NULL)
		MyServiceApi::ServiceMap[rtn] = MN + L'\\' + DN + L'\\';
	return rtn;
}

SC_HANDLE WINAPI MyOpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess)
{
	wstring tmp = MyServiceApi::ServiceMap[hSCManager];
	SC_HANDLE rtn = OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);
	PLOGD << "OpenServiceA->SCManager:" << tmp
		<< "  ,Service:"<<sc(lpServiceName) << endl;
	if (rtn != NULL)
		MyServiceApi::ServiceMap[rtn] = tmp + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sc(lpServiceName));
	return rtn;
}

SC_HANDLE WINAPI MyOpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess)
{
	wstring tmp = MyServiceApi::ServiceMap[hSCManager];
	SC_HANDLE rtn = OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
	PLOGD << "OpenServiceA->SCManager:" << tmp
		<< "  ,Service:" << sc(lpServiceName) << endl;
	if (rtn != NULL)
		MyServiceApi::ServiceMap[rtn] = tmp + sc(lpServiceName);
	return rtn;
}

