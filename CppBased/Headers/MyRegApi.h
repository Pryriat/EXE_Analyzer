#pragma once
#include"Global.h"
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif
using std::endl;
using std::wstring;
using std::map;

HOOK_TRACE_INFO RegCloseKeyHook;
HOOK_TRACE_INFO RegCreateKeyAHook;
HOOK_TRACE_INFO RegCreateKeyWHook;
HOOK_TRACE_INFO RegCreateKeyExAHook;
HOOK_TRACE_INFO RegCreateKeyExWHook;
HOOK_TRACE_INFO RegDeleteKeyAHook;
HOOK_TRACE_INFO RegDeleteKeyWHook;
HOOK_TRACE_INFO RegDeleteKeyExAHook;
HOOK_TRACE_INFO RegDeleteKeyExWHook;
HOOK_TRACE_INFO RegDeleteKeyValueAHook;
HOOK_TRACE_INFO RegDeleteKeyValueWHook;
HOOK_TRACE_INFO RegDeleteValueAHook;
HOOK_TRACE_INFO RegDeleteValueWHook;
HOOK_TRACE_INFO RegGetValueAHook;
HOOK_TRACE_INFO RegGetValueWHook;
HOOK_TRACE_INFO RegOpenKeyAHook;
HOOK_TRACE_INFO RegOpenKeyExAHook;
HOOK_TRACE_INFO RegOpenKeyWHook;
HOOK_TRACE_INFO RegOpenKeyExWHook;
HOOK_TRACE_INFO RegQueryValueAHook;
HOOK_TRACE_INFO RegQueryValueWHook;
HOOK_TRACE_INFO RegSetValueAHook;
HOOK_TRACE_INFO RegSetValueWHook;
HOOK_TRACE_INFO RegSetValueExAHook;
HOOK_TRACE_INFO RegSetValueExWHook;


typedef DWORD(__stdcall* NtQueryKeyType)(
    HANDLE  KeyHandle,
    int KeyInformationClass,
    PVOID  KeyInformation,
    ULONG  Length,
    PULONG  ResultLength);

map<HKEY, wstring> RegMap;
inline std::wstring GetName(HKEY hKey)
{
    if (RegMap.find(hKey) == RegMap.end())
    {
        std::wstring keyPath;
        if (hKey != NULL)
        {
            HMODULE dll = LoadLibrary(L"ntdll.dll");
            if (dll != NULL) 
            {
                NtQueryKeyType func = reinterpret_cast<NtQueryKeyType>(::GetProcAddress(dll, "NtQueryKey"));
                if (func != NULL) 
                {
                    DWORD size = 0;
                    DWORD result = 0;
                    result = func(hKey, 3, 0, 0, &size);
                    if (result == STATUS_BUFFER_TOO_SMALL)
                    {
                        size = size + 2;
                        wchar_t* buffer = new (std::nothrow) wchar_t[size / sizeof(wchar_t)]; // size is in bytes
                        if (buffer != NULL)
                        {
                            result = func(hKey, 3, buffer, size, &size);
                            if (result == STATUS_SUCCESS)
                            {
                                buffer[size / sizeof(wchar_t)] = L'\0';
                                keyPath = std::wstring(buffer + 2);
                            }
                            delete[] buffer;
                        }
                    }
                }
                FreeLibrary(dll);
            }
        }
        RegMap[hKey] = keyPath;
    }
    return RegMap[hKey];
}

LSTATUS WINAPI MyRegCloseKey(
    HKEY hKey
)
{
    NTSTATUS rtn = RegCloseKey(hKey);
    if ((rtn == ERROR_SUCCESS) && (RegMap.find(hKey) != RegMap.end()))
        RegMap.erase(hKey);
    PLOGD << "RegCloseKey->hKey:" << reinterpret_cast<LONG>(hKey)<<endl;
    return rtn;
}

LSTATUS WINAPI MyRegOpenKeyA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    PHKEY  phkResult
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegOpenKeyA(hKey, lpSubKey, phkResult);
    PLOGD << "RegOpenKeyA->Key" << tmp
        << "  ,SubKey:" << sc(lpSubKey)
        << "  ,result:" << *phkResult << endl;
    if ( (lpSubKey != NULL) && (rtn == ERROR_SUCCESS) )
        RegMap[*phkResult] = tmp + L"\\" + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpSubKey);
    return rtn;
}

LSTATUS WINAPI MyRegOpenKeyW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    PHKEY  phkResult
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegOpenKeyW(hKey, lpSubKey, phkResult);
    PLOGD << "RegOpenKeyW->Key" << tmp
        << "  ,SubKey:" << sc(lpSubKey)
        << "  ,result:" << *phkResult << endl;
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + lpSubKey;
    return rtn;
}

LSTATUS WINAPI MyRegCreateKeyA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    PHKEY  phkResult
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegCreateKeyA(hKey, lpSubKey, phkResult);
    PLOGD << "RegCreateKeyA->Key" << tmp
        << "  ,SubKey:" << sc(lpSubKey)
        << "  ,result:" << *phkResult << endl;
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpSubKey);
    return rtn;
}

LSTATUS WINAPI MyRegCreateKeyW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    PHKEY  phkResult
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegCreateKeyW(hKey, lpSubKey, phkResult);
    PLOGD << "RegCreateKeyW->Key" << tmp
        << "  ,SubKey:" << sc(lpSubKey)
        << "  ,result:" << *phkResult << endl;
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + lpSubKey;
    return rtn;
}

LSTATUS WINAPI MyRegCreateKeyExA(
    HKEY                        hKey,
    LPCSTR                      lpSubKey,
    DWORD                       Reserved,
    LPSTR                       lpClass,
    DWORD                       dwOptions,
    REGSAM                      samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY                       phkResult,
    LPDWORD                     lpdwDisposition
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    PLOGD << "RegCreateKeyExA->Key" << tmp
        << "  ,SubKey:" << sc(lpSubKey)
        << "  ,result:" << *phkResult << endl;
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpSubKey);
    return rtn;
}

LSTATUS WINAPI MyRegCreateKeyExW(
    HKEY                        hKey,
    LPCWSTR                      lpSubKey,
    DWORD                       Reserved,
    LPWSTR                       lpClass,
    DWORD                       dwOptions,
    REGSAM                      samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY                       phkResult,
    LPDWORD                     lpdwDisposition
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    PLOGD << "RegCreateKeyExW->Key" << tmp
        << "  ,SubKey:" << sc(lpSubKey)
        << "  ,result:" << *phkResult << endl;
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + lpSubKey;
    return rtn;
}

LSTATUS WINAPI MyRegOpenKeyExA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    DWORD  ulOptions,
    REGSAM samDesired,
    PHKEY  phkResult
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    PLOGD << "RegOpenKeyExA->Key" << tmp
        << "  ,SubKey:" << sc(lpSubKey)
        << "  ,result:" << *phkResult << endl;
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpSubKey);
    return rtn;
}

LSTATUS WINAPI MyRegOpenKeyExW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    DWORD  ulOptions,
    REGSAM samDesired,
    PHKEY  phkResult
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    PLOGD << "RegOpenKeyExW->Key" << tmp
        << "  ,SubKey:" << sc(lpSubKey)
        << "  ,result:" << *phkResult << endl;
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + lpSubKey;
    return rtn;
}

LSTATUS WINAPI MyRegDeleteKeyA(
    HKEY   hKey,
    LPCSTR lpSubKey
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteKeyA(hKey, lpSubKey);
    PLOGD << "RegDeleteKeyA->Key" << tmp
        << "  ,SubKey" << sc(lpSubKey) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegDeleteKeyExA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    REGSAM samDesired,
    DWORD  Reserved
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteKeyExA(hKey, lpSubKey, samDesired, Reserved);
    PLOGD << "RegDeleteKeyExA->Key" << tmp
        << "  ,SubKey" << sc(lpSubKey) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegDeleteKeyW(
    HKEY   hKey,
    LPCWSTR lpSubKey
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteKeyW(hKey, lpSubKey);
    PLOGD << "RegDeleteKeyW->Key" << tmp
        << "  ,SubKey" << sc(lpSubKey) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegDeleteKeyExW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    REGSAM samDesired,
    DWORD  Reserved
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteKeyExW(hKey, lpSubKey, samDesired, Reserved);
    PLOGD << "RegDeleteKeyExW->Key" << tmp
        << "  ,SubKey" << sc(lpSubKey) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegDeleteKeyValueA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    LPCSTR lpValueName
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteKeyValueA(hKey, lpSubKey, lpValueName);
    PLOGD << "RegDeleteKeyValueA->Key" << tmp
        << "  ,SubKey" << sc(lpSubKey) 
        <<"  ,ValueName"<<sc(lpValueName)<<endl;
    return rtn;
}

LSTATUS WINAPI MyRegDeleteKeyValueW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    LPCWSTR lpValueName
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteKeyValueW(hKey, lpSubKey, lpValueName);
    PLOGD << "RegDeleteKeyValueA->Key" << tmp
        << "  ,SubKey" << sc(lpSubKey)
        << "  ,ValueName" << sc(lpValueName) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegDeleteValueA(
    HKEY   hKey,
    LPCSTR lpValueName
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteValueA(hKey, lpValueName);
    PLOGD << "RegDeleteKeyValueA->Key" << tmp
        << "  ,ValueName" << sc(lpValueName) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegDeleteValueW(
    HKEY   hKey,
    LPCWSTR lpValueName
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteValueW(hKey, lpValueName);
    PLOGD << "RegDeleteKeyValueA->Key" << tmp
        << "  ,ValueName" << sc(lpValueName) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegGetValueA(
    HKEY    hKey,
    LPCSTR  lpSubKey,
    LPCSTR  lpValue,
    DWORD   dwFlags,
    LPDWORD pdwType,
    PVOID   pvData,
    LPDWORD pcbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegGetValueA(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
    PLOGD << "RegGetVlueA->Key:" << tmp
        << "  ,SbuKey" << sc(lpSubKey)
        << "  ,Value:" << sc(lpValue) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegGetValueW(
    HKEY    hKey,
    LPCWSTR  lpSubKey,
    LPCWSTR  lpValue,
    DWORD   dwFlags,
    LPDWORD pdwType,
    PVOID   pvData,
    LPDWORD pcbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegGetValueW(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
    PLOGD << "RegGetVlueA->Key:" << tmp
        << "  ,SbuKey" << sc(lpSubKey)
        << "  ,Value:" << sc(lpValue) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegQueryValueA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    LPSTR  lpData,
    PLONG  lpcbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegQueryValueA(hKey, lpSubKey, lpData, lpcbData);
    PLOGD << "RegQueryValueA->Key:" << tmp
        << "  ,SubKey" << sc(lpSubKey) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegQueryValueW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    LPWSTR  lpData,
    PLONG  lpcbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegQueryValueW(hKey, lpSubKey, lpData, lpcbData);
    PLOGD << "RegQueryValueW->Key:" << tmp
        << "  ,SubKey" << sc(lpSubKey) << endl;
    return rtn;
}

LSTATUS WINAPI RegQueryValueExA(
    HKEY    hKey,
    LPCSTR  lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE  lpData,
    LPDWORD lpcbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegQueryValueExA(hKey, lpValueName, lpReserved, lpType ,lpData, lpcbData);
    PLOGD << "RegQueryValueExA->Key:" << tmp
        << "  ,Value" << sc(lpValueName) << endl;
    return rtn;
}

LSTATUS WINAPI RegQueryValueExW(
    HKEY    hKey,
    LPCWSTR  lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE  lpData,
    LPDWORD lpcbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    PLOGD << "RegQueryValueExW->Key:" << tmp
        << "  ,Value" << sc(lpValueName) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegSetValueA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    DWORD  dwType,
    LPCSTR lpData,
    DWORD  cbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegSetValueA(hKey, lpSubKey, dwType, lpData, cbData);
    PLOGD << "RegSetValueA->Key:" << tmp
        << "  ,Subkey:" << sc(lpSubKey)
        << "  ,Data:" << sc(lpData) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegSetValueW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    DWORD  dwType,
    LPCWSTR lpData,
    DWORD  cbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegSetValueW(hKey, lpSubKey, dwType, lpData, cbData);
    PLOGD << "RegSetValueW->Key:" << tmp
        << "  ,Subkey:" << sc(lpSubKey)
        <<"  ,Data:"<<sc(lpData)<< endl;
    return rtn;
}

LSTATUS WINAPI MyRegSetValueExA(
    HKEY       hKey,
    LPCSTR     lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE* lpData,
    DWORD      cbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    PLOGD << "RegSetValueA->Key:" << tmp
        << "  ,ValueName:" << sc(lpValueName) << endl;
    return rtn;
}

LSTATUS WINAPI MyRegSetValueExW(
    HKEY       hKey,
    LPCWSTR     lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE* lpData,
    DWORD      cbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    PLOGD << "RegSetValueW->Key:" << tmp
        << "  ,ValueName:" << sc(lpValueName) << endl;
    return rtn;
}

void InitRegApi()
{
    Check("RegCloseKey", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegCloseKey"), MyRegCloseKey, NULL, &RegCloseKeyHook));
    Check("RegCreateKeyA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegCreateKeyA"), MyRegCreateKeyA, NULL, &RegCreateKeyAHook));
    Check("RegCreateKeyW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegCreateKeyW"), MyRegCreateKeyW, NULL, &RegCreateKeyWHook));
    Check("RegCreateKeyExA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegCreateKeyExA"), MyRegCreateKeyExA, NULL, &RegCreateKeyExAHook));
    Check("RegCreateKeyExW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegCreateKeyExW"), MyRegCreateKeyExW, NULL, &RegCreateKeyExWHook));
    Check("RegDeleteKeyA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteKeyA"), MyRegDeleteKeyA, NULL, &RegDeleteKeyAHook));
    Check("RegDeleteKeyW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteKeyW"), MyRegDeleteKeyW, NULL, &RegDeleteKeyWHook));
    Check("RegDeleteKeyExA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteKeyExA"), MyRegDeleteKeyExA, NULL, &RegDeleteKeyExAHook));
    Check("RegDeleteKeyExW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteKeyExW"), MyRegDeleteKeyExW, NULL, &RegDeleteKeyExWHook));
    Check("RegDeleteKeyValueA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteKeyValueA"), MyRegDeleteKeyValueA, NULL, &RegDeleteKeyValueAHook));
    Check("RegDeleteKeyValueW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteKeyValueW"), MyRegDeleteKeyValueW, NULL, &RegDeleteKeyValueWHook));
    Check("RegDeleteValueA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteValueA"), MyRegDeleteValueA, NULL, &RegDeleteValueAHook));
    Check("RegDeleteValueW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteValueW"), MyRegDeleteValueW, NULL, &RegDeleteValueWHook));
    Check("RegGetValueW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegGetValueW"), MyRegGetValueW, NULL, &RegGetValueWHook));
    Check("RegGetValueA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegGetValueA"), MyRegGetValueA, NULL, &RegGetValueAHook));
    Check("RegOpenKeyA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegOpenKeyA"), MyRegOpenKeyA, NULL, &RegOpenKeyAHook));
    Check("RegOpenKeyW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegOpenKeyW"), MyRegOpenKeyW, NULL, &RegOpenKeyWHook));
    Check("RegOpenKeyExW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegOpenKeyExW"), MyRegOpenKeyExW, NULL, &RegOpenKeyExWHook));
    Check("RegOpenKeyExA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegOpenKeyExA"), MyRegOpenKeyExA, NULL, &RegOpenKeyExAHook));
    Check("RegQueryValueA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegQueryValueA"), MyRegQueryValueA, NULL, &RegQueryValueAHook));
    Check("RegQueryValueW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegQueryValueW"), MyRegQueryValueW, NULL, &RegQueryValueWHook));
    Check("RegSetValueA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegSetValueA"), MyRegSetValueA, NULL, &RegSetValueAHook));
    Check("RegSetValueW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegSetValueW"), MyRegSetValueW, NULL, &RegSetValueWHook));
    Check("RegSetValueExW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegSetValueExW"), MyRegSetValueExW, NULL, &RegSetValueExWHook));
    Check("RegSetValueExA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegSetValueExA"), MyRegSetValueExA, NULL, &RegSetValueExAHook));

    ULONG ACLEntries[1] = { 0 };

    Check("RegCloseKey", LhSetExclusiveACL(ACLEntries, 1, &RegCloseKeyHook));
    Check("RegCreateKeyA", LhSetExclusiveACL(ACLEntries, 1, &RegCreateKeyAHook));
    Check("RegCreateKeyW", LhSetExclusiveACL(ACLEntries, 1, &RegCreateKeyWHook));
    Check("RegCreateKeyExA", LhSetExclusiveACL(ACLEntries, 1, &RegCreateKeyExAHook));
    Check("RegCreateKeyExW", LhSetExclusiveACL(ACLEntries, 1, &RegCreateKeyExWHook));
    Check("RegDeleteKeyA", LhSetExclusiveACL(ACLEntries, 1, &RegDeleteKeyAHook));
    Check("RegDeleteKeyW", LhSetExclusiveACL(ACLEntries, 1, &RegDeleteKeyWHook));
    Check("RegDeleteKeyExA", LhSetExclusiveACL(ACLEntries, 1, &RegDeleteKeyExAHook));
    Check("RegDeleteKeyExW", LhSetExclusiveACL(ACLEntries, 1, &RegDeleteKeyExWHook));
    Check("RegDeleteKeyValueA", LhSetExclusiveACL(ACLEntries, 1, &RegDeleteKeyValueAHook));
    Check("RegDeleteKeyValueW", LhSetExclusiveACL(ACLEntries, 1, &RegDeleteKeyValueWHook));
    Check("RegDeleteValueA", LhSetExclusiveACL(ACLEntries, 1, &RegDeleteValueAHook));
    Check("RegDeleteValueW", LhSetExclusiveACL(ACLEntries, 1, &RegDeleteValueWHook));
    Check("RegGetValueW", LhSetExclusiveACL(ACLEntries, 1, &RegGetValueWHook));
    Check("RegGetValueA", LhSetExclusiveACL(ACLEntries, 1, &RegGetValueAHook));
    Check("RegOpenKeyA", LhSetExclusiveACL(ACLEntries, 1, &RegOpenKeyAHook));
    Check("RegOpenKeyW", LhSetExclusiveACL(ACLEntries, 1, &RegOpenKeyWHook));
    Check("RegOpenKeyExW", LhSetExclusiveACL(ACLEntries, 1, &RegOpenKeyExWHook));
    Check("RegOpenKeyExA", LhSetExclusiveACL(ACLEntries, 1, &RegOpenKeyExAHook));
    Check("RegQueryValueA", LhSetExclusiveACL(ACLEntries, 1, &RegQueryValueAHook));
    Check("RegQueryValueW", LhSetExclusiveACL(ACLEntries, 1, &RegQueryValueWHook));
    Check("RegSetValueA", LhSetExclusiveACL(ACLEntries, 1, &RegSetValueAHook));
    Check("RegSetValueW", LhSetExclusiveACL(ACLEntries, 1, &RegSetValueWHook));
    Check("RegSetValueExW", LhSetExclusiveACL(ACLEntries, 1, &RegSetValueExWHook));
    Check("RegSetValueExA", LhSetExclusiveACL(ACLEntries, 1, &RegSetValueExAHook));
}