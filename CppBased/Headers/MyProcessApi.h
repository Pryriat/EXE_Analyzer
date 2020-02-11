#pragma once
#include"Global.h"


using std::endl;

BOOL ProcessApiEnable = true;

HOOK_TRACE_INFO CreateProcessAHook;
HOOK_TRACE_INFO CreateProcessWHook;
HOOK_TRACE_INFO CreateRemoteThreadHook;
HOOK_TRACE_INFO CreateRemoteThreadExHook;
HOOK_TRACE_INFO CreateThreadHook;
HOOK_TRACE_INFO OpenProcessHook;
HOOK_TRACE_INFO TerminateProcessHook;
HOOK_TRACE_INFO TerminateThreadHook;


BOOL WINAPI MyCreateProcessA(
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
    PLOGD << "CreateProcessA->AppName:" << sc(lpApplicationName)
        << ", Commandline:" << sc(lpCommandLine)
        << ", Status:" << rtn << endl;
    if (rtn)
    {
        NTSTATUS nt = RhInjectLibrary(lpProcessInformation->dwProcessId, 0, EASYHOOK_INJECT_DEFAULT, NULL, const_cast<WCHAR*>(L".\\x64\\Debug\\hook.dll"), NULL, 0);
        if (ERROR(nt))
            PLOGD << RtlGetLastErrorString() << endl;
        else
        {
            PLOGD << "Dll Injiect to New Process Success"<<endl;
        }
    }
    return rtn;
}

BOOL WINAPI MyCreateProcessW(
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
    if (rtn)
    {
        NTSTATUS nt = RhInjectLibrary(lpProcessInformation->dwProcessId, 0, EASYHOOK_INJECT_DEFAULT, NULL, const_cast<WCHAR*>(L".\\x64\\Debug\\hook.dll"), NULL, 0);
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

HANDLE WINAPI MyCreateRemoteThread(
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
    if (lpThreadId != NULL)
        PLOGD << "CreateRemoteThread->TargetApp:" << GetProcessNameByHandle(hProcess)
            << ", ThreadId:" << *lpThreadId 
            <<", StartAddress:"<< reinterpret_cast<ULONG>(lpStartAddress)<<endl;
    else
        PLOGD << "CreateRemoteThread->TargetApp:" << GetProcessNameByHandle(hProcess)
        << ", StartAddress:" << reinterpret_cast<ULONG>(lpStartAddress) << endl;
    return rtn;
}

HANDLE WINAPI MyCreateRemoteThreadEx(
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
    if(lpThreadId != NULL)
        PLOGD << "CreateRemoteThreadEx->TargetApp:" << GetProcessNameByHandle(hProcess)
            << ", ThreadId: " << *lpThreadId 
            << ", StartAddress:" << reinterpret_cast<ULONG>(lpStartAddress) << endl;
    else
        PLOGD << "CreateRemoteThreadEx->TargetApp:" << GetProcessNameByHandle(hProcess)
        << ", StartAddress:" << reinterpret_cast<ULONG>(lpStartAddress) << endl;
    return rtn;
}

HANDLE WINAPI MyCreateThread(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
)
{
    HANDLE rtn = CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    if(lpThreadId)
        PLOGD << "CreateThread->ThreadId: " << *lpThreadId
            << ", StartAddress:" << reinterpret_cast<ULONG>(lpStartAddress) << endl;
    else
        PLOGD << "CreateThread->"
        << ", StartAddress:" << reinterpret_cast<ULONG>(lpStartAddress) << endl;
    return rtn;
}

HANDLE WINAPI MyOpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
)
{
    HANDLE rtn = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    if (rtn != NULL)
    {
        std::wstring c = GetProcessNameByHandle(rtn);
        if (dwProcessId != GetCurrentProcessId() && c.size()>0)
            PLOGD << "OpenProcess->TargetApp:" << c << endl;
    }
    
    return rtn;
}

HANDLE WINAPI MyOpenThread(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwThreadId
)
{
    HANDLE rtn = OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
    if(dwThreadId != GetCurrentThreadId())
        PLOGD << "OpenThread->TargetApp:" << GetProcessNameByHandle(GetCurrentProcess()) << endl;
    return rtn;
}

BOOL WINAPI MyTerminateProcess(
    HANDLE hProcess,
    UINT   uExitCode
)
{
    BOOL rtn = TerminateProcess(hProcess, uExitCode);
    PLOGD << "TerMinateProcess->TargetApp:" << GetProcessNameByHandle(hProcess)
        << ", ExitCode:" << uExitCode
        << ", Status:" << rtn<<endl;
    return rtn;
}

BOOL WINAPI MyTerminateThread(HANDLE hThread, DWORD dwExitCode)
{
    BOOL rtn = TerminateThread(hThread, dwExitCode);
    PLOGD << "TerMinateProcess->TargetApp:" << GetProcessNameByHandle(GetCurrentProcess())
        << ", ExitCode:" << dwExitCode
        << ", Status:" << rtn << endl;
    return rtn;
}

inline void InitProcessApi64()
{
    Check("CreateProcessA" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateProcessA"), MyCreateProcessA, NULL, &CreateProcessAHook));
    Check("CreateProcessW" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateProcessW"), MyCreateProcessW, NULL, &CreateProcessWHook));
    Check("CreateRemoteThread" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateRemoteThread"), MyCreateRemoteThread, NULL, &CreateRemoteThreadHook));
    Check("CreateRemoteThreadEx" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateRemoteThreadEx"), MyCreateRemoteThreadEx, NULL, &CreateRemoteThreadExHook));
    Check("CreateThread" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateThread"), MyCreateThread, NULL, &CreateThreadHook));
    Check("OpenProcess" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "OpenProcess"), MyOpenProcess, NULL, &OpenProcessHook));
    Check("TerminateProcess" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "TerminateProcess"), MyTerminateProcess, NULL, &TerminateProcessHook));
    Check("TerminateThread" ,LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "TerminateThread"), MyTerminateThread, NULL, &TerminateThreadHook));

    ULONG ACLEntries[1] = { 0 };
    Check("CreateProcessA" ,LhSetExclusiveACL(ACLEntries, 1, &CreateProcessAHook));
    Check("CreateProcessW" ,LhSetExclusiveACL(ACLEntries, 1, &CreateProcessWHook));
    Check("CreateRemoteThread" ,LhSetExclusiveACL(ACLEntries, 1, &CreateRemoteThreadHook));
    Check("CreateRemoteThreadEx" ,LhSetExclusiveACL(ACLEntries, 1, &CreateRemoteThreadExHook));
    Check("CreateThread" ,LhSetExclusiveACL(ACLEntries, 1, &CreateThreadHook));
    Check("OpenProcess" ,LhSetExclusiveACL(ACLEntries, 1, &OpenProcessHook));
    Check("TerminateProcess" ,LhSetExclusiveACL(ACLEntries, 1, &TerminateProcessHook));
    Check("TerminateThread" ,LhSetExclusiveACL(ACLEntries, 1, &TerminateThreadHook));
}

inline void InitProcessApi32()
{
    Check("CreateProcessA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateProcessA"), MyCreateProcessA, NULL, &CreateProcessAHook));
    Check("CreateProcessW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateProcessW"), MyCreateProcessW, NULL, &CreateProcessWHook));
    Check("CreateRemoteThread", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateRemoteThread"), MyCreateRemoteThread, NULL, &CreateRemoteThreadHook));
    Check("CreateRemoteThreadEx", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateRemoteThreadEx"), MyCreateRemoteThreadEx, NULL, &CreateRemoteThreadExHook));
    Check("CreateThread", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateThread"), MyCreateThread, NULL, &CreateThreadHook));
    Check("OpenProcess", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "OpenProcess"), MyOpenProcess, NULL, &OpenProcessHook));
    Check("TerminateProcess", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "TerminateProcess"), MyTerminateProcess, NULL, &TerminateProcessHook));
    Check("TerminateThread", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "TerminateThread"), MyTerminateThread, NULL, &TerminateThreadHook));

    ULONG ACLEntries[1] = { 0 };
    Check("CreateProcessA", LhSetExclusiveACL(ACLEntries, 1, &CreateProcessAHook));
    Check("CreateProcessW", LhSetExclusiveACL(ACLEntries, 1, &CreateProcessWHook));
    Check("CreateRemoteThread", LhSetExclusiveACL(ACLEntries, 1, &CreateRemoteThreadHook));
    Check("CreateRemoteThreadEx", LhSetExclusiveACL(ACLEntries, 1, &CreateRemoteThreadExHook));
    Check("CreateThread", LhSetExclusiveACL(ACLEntries, 1, &CreateThreadHook));
    Check("OpenProcess", LhSetExclusiveACL(ACLEntries, 1, &OpenProcessHook));
    Check("TerminateProcess", LhSetExclusiveACL(ACLEntries, 1, &TerminateProcessHook));
    Check("TerminateThread", LhSetExclusiveACL(ACLEntries, 1, &TerminateThreadHook));
}