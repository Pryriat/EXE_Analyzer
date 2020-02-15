#pragma once
#include"Global.h"
#include<WinSock2.h>
#pragma comment(lib, "Ws2_32.lib")
#include <comdef.h>
using std::endl;
using std::map;
using std::wstring;

typedef struct Message
{
    char Processname[260];
    char Data[5000];
}MS, *PMS;
SOCKADDR_IN addr_Clt;
sockaddr_in servAddr;
std::string buffer;
void UDPSend(const char* ProcessName, const SIZE_T& ProcessNameLength, const char* Data, const SIZE_T& DataLength);
class MyProcessApi
{
public:
    static Level Lv;
    static BOOL ProcessApiEnable;
    static SOCKET MyProcessApiSocket;
    static HOOK_TRACE_INFO CreateProcessAHook;
    static HOOK_TRACE_INFO CreateProcessWHook;
    static HOOK_TRACE_INFO CreateRemoteThreadHook;
    static HOOK_TRACE_INFO CreateRemoteThreadExHook;
    static HOOK_TRACE_INFO CreateThreadHook;
    static HOOK_TRACE_INFO OpenProcessHook;
    static HOOK_TRACE_INFO TerminateProcessHook;
    static HOOK_TRACE_INFO TerminateThreadHook; 
    static std::map<HANDLE, std::wstring> ProcMap;
    static std::map<HANDLE, std::wstring> ThreadMap;
    static void* out;
    static void SetLv(Level Lv)
    {
        MyProcessApi::Lv = Lv;
    }

    static BOOL WINAPI MyCreateProcessA(
        LPCSTR                lpApplicationName,
        LPSTR                 lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCSTR                lpCurrentDirectory,
        LPSTARTUPINFOA        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    );
    static BOOL WINAPI MyCreateProcessW(
        LPCWSTR                lpApplicationName,
        LPWSTR                 lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCWSTR                lpCurrentDirectory,
        LPSTARTUPINFOW        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    );
    static HANDLE WINAPI MyCreateRemoteThread(
        HANDLE                 hProcess,
        LPSECURITY_ATTRIBUTES  lpThreadAttributes,
        SIZE_T                 dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID                 lpParameter,
        DWORD                  dwCreationFlags,
        LPDWORD                lpThreadId
    );
    static HANDLE WINAPI MyCreateRemoteThreadEx(
        HANDLE                       hProcess,
        LPSECURITY_ATTRIBUTES        lpThreadAttributes,
        SIZE_T                       dwStackSize,
        LPTHREAD_START_ROUTINE       lpStartAddress,
        LPVOID                       lpParameter,
        DWORD                        dwCreationFlags,
        LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
        LPDWORD                      lpThreadId
    );
    static HANDLE WINAPI MyCreateThread(
        LPSECURITY_ATTRIBUTES   lpThreadAttributes,
        SIZE_T                  dwStackSize,
        LPTHREAD_START_ROUTINE  lpStartAddress,
        __drv_aliasesMem LPVOID lpParameter,
        DWORD                   dwCreationFlags,
        LPDWORD                 lpThreadId
    );
    static HANDLE WINAPI MyOpenProcess(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwProcessId
    );
    static HANDLE WINAPI MyOpenThread(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwThreadId
    );
    static BOOL WINAPI MyTerminateProcess(
        HANDLE hProcess,
        UINT   uExitCode
    );
    static BOOL WINAPI MyTerminateThread(
        HANDLE hThread,
        DWORD dwExitCode
    );
    static void init_func(void* func)
    {
        MyProcessApi::out = func;
    }
    static inline void InitProcessApi64();
    static inline void InitProcessApi32();
    static inline bool InitSocket();
};

Level MyProcessApi::Lv = Debug;

BOOL MyProcessApi::ProcessApiEnable = true;

HOOK_TRACE_INFO MyProcessApi::CreateProcessAHook;
HOOK_TRACE_INFO MyProcessApi::CreateProcessWHook;
HOOK_TRACE_INFO MyProcessApi::CreateRemoteThreadHook;
HOOK_TRACE_INFO MyProcessApi::CreateRemoteThreadExHook;
HOOK_TRACE_INFO MyProcessApi::CreateThreadHook;
HOOK_TRACE_INFO MyProcessApi::OpenProcessHook;
HOOK_TRACE_INFO MyProcessApi::TerminateProcessHook;
HOOK_TRACE_INFO MyProcessApi::TerminateThreadHook;
map<HANDLE, wstring> MyProcessApi::ProcMap;
map<HANDLE, wstring> MyProcessApi::ThreadMap;
void* MyProcessApi::out = NULL;
SOCKET MyProcessApi::MyProcessApiSocket;
BOOL WINAPI MyProcessApi::MyCreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    BOOL rtn = CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if(Lv > None)
        PLOGD << "CreateProcessA->AppName:" << sc(lpApplicationName)
            << ", Commandline:" << sc(lpCommandLine)
            << ", Status:" << rtn << endl;
    if (rtn)
    {
        NTSTATUS nt = RhInjectLibrary(lpProcessInformation->dwProcessId, 0, EASYHOOK_INJECT_DEFAULT, const_cast<WCHAR*>(L".\\Debug\\hook.dll"), const_cast<WCHAR*>(L".\\x64\\Debug\\hook.dll"), NULL, 0);
        if (ERROR(nt))
            PLOGD << RtlGetLastErrorString() << endl;
        else
        {
            PLOGD << "Dll Injiect to New Process Success"<<endl;
        }
    }
    return rtn;
}

BOOL WINAPI MyProcessApi::MyCreateProcessW(
    LPCWSTR                lpApplicationName,
    LPWSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR                lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    BOOL rtn = CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    std::string q = "CreateProcessW:";
    q += std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(sc(lpApplicationName))+"\n";
    buffer += q;
    if (buffer.size() > 2048)
    {
        std::string processname = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(sc(lpApplicationName));
        UDPSend(processname.c_str(), processname.size(), buffer.c_str(), buffer.size());
    }
    if (rtn)
    {
        NTSTATUS nt = RhInjectLibrary(lpProcessInformation->dwProcessId, 0, EASYHOOK_INJECT_DEFAULT, const_cast<WCHAR*>(L".\\Debug\\hook.dll"), const_cast<WCHAR*>(L".\\x64\\Debug\\hook.dll"), NULL, 0);
        if (Lv > None)
            PLOGD << "CreateProcessW->AppName:" << sc(lpApplicationName)
                << ", Commandline:" << sc(lpCommandLine)
                << ", Status:" << rtn << endl;
        if (ERROR(nt))
            PLOGD << RtlGetLastErrorString() << endl;
        else
        {
            PLOGD << "Dll Injiect to New Process Success"<<endl;
        }
    }
    return rtn;
}

HANDLE WINAPI MyProcessApi::MyCreateRemoteThread(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
)
{
    HANDLE rtn = CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    if (lpThreadId != NULL && Lv > None)
            PLOGD << "CreateRemoteThread->TargetApp:" << GetProcessNameByHandle(hProcess)
                << ", ThreadId:" << *lpThreadId 
                <<", StartAddress:"<< reinterpret_cast<ULONG>(lpStartAddress)<<endl;
    else if (Lv > None)
        PLOGD << "CreateRemoteThread->TargetApp:" << GetProcessNameByHandle(hProcess)
        << ", StartAddress:" << reinterpret_cast<ULONG>(lpStartAddress) << endl;
    return rtn;
}

HANDLE WINAPI MyProcessApi::MyCreateRemoteThreadEx(
    HANDLE                       hProcess,
    LPSECURITY_ATTRIBUTES        lpThreadAttributes,
    SIZE_T                       dwStackSize,
    LPTHREAD_START_ROUTINE       lpStartAddress,
    LPVOID                       lpParameter,
    DWORD                        dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD                      lpThreadId
)
{
    HANDLE rtn = CreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
    std::string name = "CreateThreadEx:";
    name += std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(GetProcessNameByHandle(hProcess))+"\n";
    buffer += name;
    if (buffer.size() > 2048)
    {
        std::string processname = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(GetProcessNameByHandle(hProcess));
        UDPSend(processname.c_str(), processname.size(), buffer.c_str(), buffer.size());
    }
    if(lpThreadId != NULL && Lv > None)
        PLOGD << "CreateRemoteThreadEx->TargetApp:" << GetProcessNameByHandle(hProcess)
            << ", ThreadId: " << *lpThreadId 
            << ", StartAddress:" << reinterpret_cast<ULONG>(lpStartAddress) << endl;
    else if(Lv > None)
        PLOGD << "CreateRemoteThreadEx->TargetApp:" << GetProcessNameByHandle(hProcess)
        << ", StartAddress:" << reinterpret_cast<ULONG>(lpStartAddress) << endl;
    return rtn;
}

HANDLE WINAPI MyProcessApi::MyCreateThread(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
)
{
    HANDLE rtn = CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    if(lpThreadId && Lv > Critial)
        PLOGD << "CreateThread->ThreadId: " << *lpThreadId
            << ", StartAddress:" << reinterpret_cast<ULONG>(lpStartAddress) << endl;
    else if(Lv>Critial)
        PLOGD << "CreateThread->"
        << ", StartAddress:" << reinterpret_cast<ULONG>(lpStartAddress) << endl;
    return rtn;
}

HANDLE WINAPI MyProcessApi::MyOpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
)
{
    HANDLE rtn = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    if (rtn != NULL)
    {
        std::wstring c = GetProcessNameByHandle(rtn);
        if (dwProcessId != GetCurrentProcessId() && c.size()>0 && Lv>Critial)
            PLOGD << "OpenProcess->TargetApp:" << c << endl;
    }
    return rtn;
}

HANDLE WINAPI MyProcessApi::MyOpenThread(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwThreadId
)
{
    HANDLE rtn = OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
    if(dwThreadId != GetCurrentThreadId() && Lv > Critial)
        PLOGD << "OpenThread->TargetApp:" << GetProcessNameByHandle(GetCurrentProcess()) << endl;
    return rtn;
}

BOOL WINAPI MyProcessApi::MyTerminateProcess(
    HANDLE hProcess,
    UINT   uExitCode
)
{
    BOOL rtn = TerminateProcess(hProcess, uExitCode);
    if(Lv > None)
        PLOGD << "TerMinateProcess->TargetApp:" << GetProcessNameByHandle(hProcess)
            << ", ExitCode:" << uExitCode
            << ", Status:" << rtn<<endl;
    return rtn;
}

BOOL WINAPI MyProcessApi::MyTerminateThread(HANDLE hThread, DWORD dwExitCode)
{
    BOOL rtn = TerminateThread(hThread, dwExitCode);
    if(Lv > Critial)
        PLOGD << "TerMinateProcess->TargetApp:" << GetProcessNameByHandle(GetCurrentProcess())
            << ", ExitCode:" << dwExitCode
            << ", Status:" << rtn << endl;
    return rtn;
}

inline void MyProcessApi::InitProcessApi64()
{
    Check("CreateProcessA" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateProcessA"), MyProcessApi::MyCreateProcessA, NULL, &MyProcessApi::CreateProcessAHook));
    Check("CreateProcessW" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateProcessW"), MyProcessApi::MyCreateProcessW, NULL, &MyProcessApi::CreateProcessWHook));
    Check("CreateRemoteThread" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateRemoteThread"), MyProcessApi::MyCreateRemoteThread, NULL, &MyProcessApi::CreateRemoteThreadHook));
    Check("CreateRemoteThreadEx" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateRemoteThreadEx"), MyProcessApi::MyCreateRemoteThreadEx, NULL, &MyProcessApi::CreateRemoteThreadExHook));
    Check("CreateThread" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateThread"), MyProcessApi::MyCreateThread, NULL, &MyProcessApi::CreateThreadHook));
    Check("OpenProcess" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "OpenProcess"), MyProcessApi::MyOpenProcess, NULL, &MyProcessApi::OpenProcessHook));
    Check("TerminateProcess" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "TerminateProcess"), MyProcessApi::MyTerminateProcess, NULL, &MyProcessApi::TerminateProcessHook));
    Check("TerminateThread" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "TerminateThread"), MyProcessApi::MyTerminateThread, NULL, &MyProcessApi::TerminateThreadHook));

    ULONG ACLEntries[1] = { 0 };
    Check("CreateProcessA" ,LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::CreateProcessAHook));
    Check("CreateProcessW" ,LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::CreateProcessWHook));
    Check("CreateRemoteThread" ,LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::CreateRemoteThreadHook));
    Check("CreateRemoteThreadEx" ,LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::CreateRemoteThreadExHook));
    Check("CreateThread" ,LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::CreateThreadHook));
    Check("OpenProcess" ,LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::OpenProcessHook));
    Check("TerminateProcess" ,LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::TerminateProcessHook));
    Check("TerminateThread" ,LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::TerminateThreadHook));
    if (InitSocket())
        PLOGD << "Socket Init Success" << endl;
    else
        PLOGD << "Socket Init Failed" << endl;
}

inline void MyProcessApi::InitProcessApi32()
{
    Check("CreateProcessA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateProcessA"), MyProcessApi::MyCreateProcessA, NULL, &MyProcessApi::CreateProcessAHook));
    Check("CreateProcessW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateProcessW"), MyProcessApi::MyCreateProcessW, NULL, &MyProcessApi::CreateProcessWHook));
    Check("CreateRemoteThread", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateRemoteThread"), MyProcessApi::MyCreateRemoteThread, NULL, &MyProcessApi::CreateRemoteThreadHook));
    Check("CreateRemoteThreadEx", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateRemoteThreadEx"), MyProcessApi::MyCreateRemoteThreadEx, NULL, &MyProcessApi::CreateRemoteThreadExHook));
    Check("CreateThread", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateThread"), MyProcessApi::MyCreateThread, NULL, &MyProcessApi::CreateThreadHook));
    Check("OpenProcess", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "OpenProcess"), MyProcessApi::MyOpenProcess, NULL, &MyProcessApi::OpenProcessHook));
    Check("TerminateProcess", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "TerminateProcess"), MyProcessApi::MyTerminateProcess, NULL, &MyProcessApi::TerminateProcessHook));
    Check("TerminateThread", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "TerminateThread"), MyProcessApi::MyTerminateThread, NULL, &MyProcessApi::TerminateThreadHook));

    ULONG ACLEntries[1] = { 0 };
    Check("CreateProcessA", LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::CreateProcessAHook));
    Check("CreateProcessW", LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::CreateProcessWHook));
    Check("CreateRemoteThread", LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::CreateRemoteThreadHook));
    Check("CreateRemoteThreadEx", LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::CreateRemoteThreadExHook));
    Check("CreateThread", LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::CreateThreadHook));
    Check("OpenProcess", LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::OpenProcessHook));
    Check("TerminateProcess", LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::TerminateProcessHook));
    Check("TerminateThread", LhSetExclusiveACL(ACLEntries, 1, &MyProcessApi::TerminateThreadHook));
    if (InitSocket())
        PLOGD << "Socket Init Success" << endl;
    else
        PLOGD << "Socket Init Failed" << endl;
}

inline bool MyProcessApi::InitSocket()
{
    if (SOCKET_ERROR == (MyProcessApi::MyProcessApiSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)))
    {
        PLOGE<<("Init socket error\n");
        return false;
    }
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servAddr.sin_port = htons((short)9999);
    int	nServAddlen = sizeof(servAddr);
    return true;
}

void UDPSend(const char* ProcessName, const SIZE_T& ProcessNameLength, const char* Data, const SIZE_T& DataLength)
{
    if (ProcessName == NULL || Data == NULL)
        PLOGE << "Data NULL" << endl;
    else if (ProcessNameLength > 260 || DataLength > 5000)
        PLOGE << "Data too long" << endl;
    else
    {
        Message tmp = { 0 };
        memcpy(tmp.Processname, ProcessName, ProcessNameLength);
        memcpy(tmp.Data, Data, DataLength);
        if (sendto(MyProcessApi::MyProcessApiSocket, (char*)&tmp, sizeof(Message), 0, (SOCKADDR*)&servAddr, sizeof(SOCKADDR)) == SOCKET_ERROR)
            PLOGE << RtlGetLastErrorString() << endl;
        else
            buffer.clear();
    }
}