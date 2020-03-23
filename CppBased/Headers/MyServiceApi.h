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
	static HOOK_TRACE_INFO CreateServiceAHook;
	static HOOK_TRACE_INFO CreateServiceWHook;
	static HOOK_TRACE_INFO SendHook;
	static map<SC_HANDLE, wstring>ServiceMap;
	static map<std::string, BOOL>ServiceSwitch;
	static USHORT Level;
	static BOOL WINAPI MyCloseServiceHandle(SC_HANDLE hSCObject);
	static SC_HANDLE WINAPI MyOpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
	static SC_HANDLE WINAPI MyOpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
	static SC_HANDLE WINAPI MyOpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess);
	static SC_HANDLE WINAPI MyOpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);
	static BOOL WINAPI MyChangeServiceConfig2A(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo);
	static SC_HANDLE WINAPI MyCreateServiceA(
		SC_HANDLE hSCManager,
		LPCSTR    lpServiceName,
		LPCSTR    lpDisplayName,
		DWORD     dwDesiredAccess,
		DWORD     dwServiceType,
		DWORD     dwStartType,
		DWORD     dwErrorControl,
		LPCSTR    lpBinaryPathName,
		LPCSTR    lpLoadOrderGroup,
		LPDWORD   lpdwTagId,
		LPCSTR    lpDependencies,
		LPCSTR    lpServiceStartName,
		LPCSTR    lpPassword
	);
	static SC_HANDLE WINAPI MyCreateServiceW(
		SC_HANDLE hSCManager,
		LPCWSTR    lpServiceName,
		LPCWSTR    lpDisplayName,
		DWORD     dwDesiredAccess,
		DWORD     dwServiceType,
		DWORD     dwStartType,
		DWORD     dwErrorControl,
		LPCWSTR    lpBinaryPathName,
		LPCWSTR    lpLoadOrderGroup,
		LPDWORD   lpdwTagId,
		LPCWSTR    lpDependencies,
		LPCWSTR    lpServiceStartName,
		LPCWSTR    lpPassword
		);
	static int WSAAPI Mysend(
		SOCKET     s,
		const char* buf,
		int        len,
		int        flags
		);
	static void PreCheck(const std::string& in, NTSTATUS Result);
	static void MyServiceApiInit();
};

HOOK_TRACE_INFO MyServiceApi::CloseServiceHandleHook;
HOOK_TRACE_INFO MyServiceApi::OpenSCManagerAHook;
HOOK_TRACE_INFO MyServiceApi::OpenSCManagerWHook;
HOOK_TRACE_INFO MyServiceApi::OpenServiceAHook;
HOOK_TRACE_INFO MyServiceApi::OpenServiceWHook;
HOOK_TRACE_INFO MyServiceApi::CreateServiceAHook;
HOOK_TRACE_INFO MyServiceApi::CreateServiceWHook;
HOOK_TRACE_INFO MyServiceApi::SendHook;
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
	MyServiceApi::PreCheck("CreateServiceA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CreateServiceA"), MyServiceApi::MyCreateServiceA, NULL, &MyServiceApi::CreateServiceAHook));
	MyServiceApi::PreCheck("CreateServiceW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CreateServiceW"), MyServiceApi::MyCreateServiceW, NULL, &MyServiceApi::CreateServiceWHook));
	MyServiceApi::PreCheck("send", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("Ws2_32")), "send"), MyServiceApi::Mysend, NULL, &MyServiceApi::SendHook));

	ULONG ACLEntries[1] = { 0 };

	::Check("CloseServiceHandle", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::CloseServiceHandleHook));
	::Check("OpenSCManagerA", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::OpenSCManagerAHook));
	::Check("OpenSCManagerW", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::OpenSCManagerWHook));
	::Check("OpenServiceA", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::OpenServiceAHook));
	::Check("OpenServiceW", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::OpenServiceWHook));
	::Check("CreateServiceA", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::CreateServiceAHook));
	::Check("CreateServiceW", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::CreateServiceWHook));
	::Check("send", LhSetExclusiveACL(ACLEntries, 1, &MyServiceApi::SendHook));
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

SC_HANDLE WINAPI MyServiceApi::MyCreateServiceA(
	SC_HANDLE hSCManager,
	LPCSTR    lpServiceName,
	LPCSTR    lpDisplayName,
	DWORD     dwDesiredAccess,
	DWORD     dwServiceType,
	DWORD     dwStartType,
	DWORD     dwErrorControl,
	LPCSTR    lpBinaryPathName,
	LPCSTR    lpLoadOrderGroup,
	LPDWORD   lpdwTagId,
	LPCSTR    lpDependencies,
	LPCSTR    lpServiceStartName,
	LPCSTR    lpPassword
)
{
	wstring tmp = MyServiceApi::ServiceMap[hSCManager];
	wstring Service = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sc(lpServiceName));
	wstring DisplayName = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sc(lpDisplayName));
	wstring BinPath = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sc(lpBinaryPathName));
	PLOGD << "CreateServiceA->Manager:" << tmp
		<< "  ,ServiceName:" << Service
		<< "  ,DisplayName:" << DisplayName
		<< "  ,BinPath:" << BinPath << endl;
	SC_HANDLE rtn = MyCreateServiceA(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName,
		lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
	return rtn;
}

SC_HANDLE WINAPI MyServiceApi::MyCreateServiceW(
	SC_HANDLE hSCManager,
	LPCWSTR    lpServiceName,
	LPCWSTR    lpDisplayName,
	DWORD     dwDesiredAccess,
	DWORD     dwServiceType,
	DWORD     dwStartType,
	DWORD     dwErrorControl,
	LPCWSTR    lpBinaryPathName,
	LPCWSTR    lpLoadOrderGroup,
	LPDWORD   lpdwTagId,
	LPCWSTR    lpDependencies,
	LPCWSTR    lpServiceStartName,
	LPCWSTR    lpPassword
	)
{
	wstring tmp = MyServiceApi::ServiceMap[hSCManager];
	PLOGD << "CreateServiceA->Manager:" << tmp
		<< "  ,ServiceName:" << sc(lpServiceName)
		<< "  ,DisplayName:" << sc(lpDisplayName)
		<< "  ,BinPath:" << sc(lpBinaryPathName) << endl;
	SC_HANDLE rtn = MyCreateServiceW(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName,
		lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
	return rtn;
}

int WSAAPI MyServiceApi::Mysend(
	SOCKET     s,
	const char* buf,
	int        len,
	int        flags
	)
{
	std::string buffer = std::string(buf, len);
	PLOGD << "Send->Buf:" << buffer;
	int rtn = send(s, buf, len, flags);
	return rtn;
}