#pragma once
#include"Global.h"
#include <functional> 
using std::map;
using std::endl;
using std::wstring;

class MyServiceApi
{
public:
	static HOOK_TRACE_INFO CloseServiceHandleHook;
	static HOOK_TRACE_INFO OpenSCManagerAHook;
	static HOOK_TRACE_INFO OpenSCManagerWHook;
	static HOOK_TRACE_INFO OpenServiceAHook;
	static HOOK_TRACE_INFO OpenServiceWHook;
	static map<SC_HANDLE, wstring>ServiceMap;
	static map<std::string, BOOL>ServiceSwitch;
	static USHORT Level;
	static BOOL WINAPI MyCloseServiceHandle(SC_HANDLE hSCObject);
	static SC_HANDLE WINAPI MyOpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
	static SC_HANDLE WINAPI MyOpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
	static SC_HANDLE WINAPI MyOpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess);
	static SC_HANDLE WINAPI MyOpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);
	static BOOL WINAPI MyChangeServiceConfig2A(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo);
	static void PreCheck(const std::string& in, NTSTATUS Result);
	static void MyServiceApiInit();
};

HOOK_TRACE_INFO MyServiceApi::CloseServiceHandleHook;
HOOK_TRACE_INFO MyServiceApi::OpenSCManagerAHook;
HOOK_TRACE_INFO MyServiceApi::OpenSCManagerWHook;
HOOK_TRACE_INFO MyServiceApi::OpenServiceAHook;
HOOK_TRACE_INFO MyServiceApi::OpenServiceWHook;
map<SC_HANDLE, wstring> MyServiceApi::ServiceMap;
map<std::string, BOOL> MyServiceApi::ServiceSwitch;
USHORT MyServiceApi::Level;

void MyServiceApi::MyServiceApiInit()
{
	MyServiceApi::PreCheck("CloseServiceHandle", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CloseServiceHandle"), MyServiceApi::MyCloseServiceHandle, NULL, &MyServiceApi::CloseServiceHandleHook));
	MyServiceApi::PreCheck("OpenSCManagerA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "OpenSCManagerA"), MyServiceApi::MyOpenSCManagerA, NULL, &MyServiceApi::OpenSCManagerAHook));
	MyServiceApi::PreCheck("OpenSCManagerW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "OpenSCManagerW"), MyServiceApi::MyOpenSCManagerW, NULL, &MyServiceApi::OpenSCManagerWHook));
	MyServiceApi::PreCheck("OpenServiceA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "OpenServiceA"), MyServiceApi::MyOpenServiceA, NULL, &MyServiceApi::OpenServiceAHook));
	MyServiceApi::PreCheck("OpenServiceW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "OpenServiceW"), MyServiceApi::MyOpenServiceW, NULL, &MyServiceApi::OpenServiceWHook));

	ULONG ACLEntries[1] = { 0 };

	::Check("CloseServiceHandle", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::CloseServiceHandleHook));
	::Check("OpenSCManagerA", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::OpenSCManagerAHook));
	::Check("OpenSCManagerW", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::OpenSCManagerWHook));
	::Check("OpenServiceA", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::OpenServiceAHook));
	::Check("OpenServiceW", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::OpenServiceWHook));
}

void MyServiceApi::PreCheck(const std::string& in, NTSTATUS Result)
{
	if (FAILED(Result))
		PLOGE << "Hook " << in << " Error:" << RtlGetLastErrorString() << std::endl;
	else
		MyServiceApi::ServiceSwitch[in] = true;
}

BOOL WINAPI MyServiceApi::MyCloseServiceHandle(SC_HANDLE hSCObject)
{
	BOOL rtn = CloseServiceHandle(hSCObject);
	if (rtn)
		MyServiceApi::ServiceMap.erase(hSCObject);
	PLOGD << "CloseServiceHandle->Handle:" << reinterpret_cast<ULONG>(hSCObject) << endl;
	return rtn;
}

SC_HANDLE WINAPI MyServiceApi::MyOpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess)
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

SC_HANDLE WINAPI MyServiceApi::MyOpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess)
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

SC_HANDLE WINAPI MyServiceApi::MyOpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess)
{
	wstring tmp = MyServiceApi::ServiceMap[hSCManager];
	SC_HANDLE rtn = OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);
	PLOGD << "OpenServiceA->SCManager:" << tmp
		<< "  ,Service:"<<sc(lpServiceName) << endl;
	if (rtn != NULL)
		MyServiceApi::ServiceMap[rtn] = tmp + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sc(lpServiceName));
	return rtn;
}

SC_HANDLE WINAPI MyServiceApi::MyOpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess)
{
	wstring tmp = MyServiceApi::ServiceMap[hSCManager];
	SC_HANDLE rtn = OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
	PLOGD << "OpenServiceA->SCManager:" << tmp
		<< "  ,Service:" << sc(lpServiceName) << endl;
	if (rtn != NULL)
		MyServiceApi::ServiceMap[rtn] = tmp + sc(lpServiceName);
	return rtn;
}

