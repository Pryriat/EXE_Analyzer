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
typedef DWORD(__stdcall* NtQueryKeyType)(
    HANDLE  KeyHandle,
    int KeyInformationClass,
    PVOID  KeyInformation,
    ULONG  Length,
    PULONG  ResultLength);

class MyRegApi
{
public:
    static std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> RegTime;
    static std::wstring_convert<std::codecvt_utf8<wchar_t>> WC;
    static SOCKET RegSocket;
    static SOCKADDR_IN RegServer;
    static Message* RegMessage;
    static std::wstringstream RegBuffer;

    static map<HKEY, wstring> RegMap;
    static Level Lv;
    static HOOK_TRACE_INFO RegCloseKeyHook;
    static HOOK_TRACE_INFO RegCreateKeyAHook;
    static HOOK_TRACE_INFO RegCreateKeyWHook;
    static HOOK_TRACE_INFO RegCreateKeyExAHook;
    static HOOK_TRACE_INFO RegCreateKeyExWHook;
    static HOOK_TRACE_INFO RegDeleteKeyAHook;
    static HOOK_TRACE_INFO RegDeleteKeyWHook;
    static HOOK_TRACE_INFO RegDeleteKeyExAHook;
    static HOOK_TRACE_INFO RegDeleteKeyExWHook;
    static HOOK_TRACE_INFO RegDeleteKeyValueAHook;
    static HOOK_TRACE_INFO RegDeleteKeyValueWHook;
    static HOOK_TRACE_INFO RegDeleteValueAHook;
    static HOOK_TRACE_INFO RegDeleteValueWHook;
    static HOOK_TRACE_INFO RegGetValueAHook;
    static HOOK_TRACE_INFO RegGetValueWHook;
    static HOOK_TRACE_INFO RegOpenKeyAHook;
    static HOOK_TRACE_INFO RegOpenKeyExAHook;
    static HOOK_TRACE_INFO RegOpenKeyWHook;
    static HOOK_TRACE_INFO RegOpenKeyExWHook;
    static HOOK_TRACE_INFO RegQueryValueAHook;
    static HOOK_TRACE_INFO RegQueryValueWHook;
    static HOOK_TRACE_INFO RegSetValueAHook;
    static HOOK_TRACE_INFO RegSetValueWHook;
    static HOOK_TRACE_INFO RegSetValueExAHook;
    static HOOK_TRACE_INFO RegSetValueExWHook;

    static inline std::wstring GetName(HKEY hKey);
    static inline void UdpSend();
    static void SetLv(Level Lv)
    {
        MyRegApi::Lv = Lv;
    }
    static LSTATUS WINAPI MyRegCloseKey(
        HKEY hKey
    );
    static LSTATUS WINAPI MyRegOpenKeyA(
        HKEY   hKey,
        LPCSTR lpSubKey,
        PHKEY  phkResult
    );
    static LSTATUS WINAPI MyRegOpenKeyW(
        HKEY   hKey,
        LPCWSTR lpSubKey,
        PHKEY  phkResult
    );
    static LSTATUS WINAPI MyRegCreateKeyA(
        HKEY   hKey,
        LPCSTR lpSubKey,
        PHKEY  phkResult
    );
    static LSTATUS WINAPI MyRegCreateKeyW(
        HKEY   hKey,
        LPCWSTR lpSubKey,
        PHKEY  phkResult
    );
    static LSTATUS WINAPI MyRegCreateKeyExA(
        HKEY                        hKey,
        LPCSTR                      lpSubKey,
        DWORD                       Reserved,
        LPSTR                       lpClass,
        DWORD                       dwOptions,
        REGSAM                      samDesired,
        const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        PHKEY                       phkResult,
        LPDWORD                     lpdwDisposition
    );
    static LSTATUS WINAPI MyRegCreateKeyExW(
        HKEY                        hKey,
        LPCWSTR                      lpSubKey,
        DWORD                       Reserved,
        LPWSTR                       lpClass,
        DWORD                       dwOptions,
        REGSAM                      samDesired,
        const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        PHKEY                       phkResult,
        LPDWORD                     lpdwDisposition
    );
    static LSTATUS WINAPI MyRegOpenKeyExA(
        HKEY   hKey,
        LPCSTR lpSubKey,
        DWORD  ulOptions,
        REGSAM samDesired,
        PHKEY  phkResult
    );
    static LSTATUS WINAPI MyRegOpenKeyExW(
        HKEY   hKey,
        LPCWSTR lpSubKey,
        DWORD  ulOptions,
        REGSAM samDesired,
        PHKEY  phkResult
    );
    static LSTATUS WINAPI MyRegDeleteKeyA(
        HKEY   hKey,
        LPCSTR lpSubKey
    );
    static LSTATUS WINAPI MyRegDeleteKeyExA(
        HKEY   hKey,
        LPCSTR lpSubKey,
        REGSAM samDesired,
        DWORD  Reserved
    );
    static LSTATUS WINAPI MyRegDeleteKeyW(
        HKEY   hKey,
        LPCWSTR lpSubKey
    );
    static LSTATUS WINAPI MyRegDeleteKeyExW(
        HKEY   hKey,
        LPCWSTR lpSubKey,
        REGSAM samDesired,
        DWORD  Reserved
    );
    static LSTATUS WINAPI MyRegDeleteKeyValueA(
        HKEY   hKey,
        LPCSTR lpSubKey,
        LPCSTR lpValueName
    );
    static LSTATUS WINAPI MyRegDeleteKeyValueW(
        HKEY   hKey,
        LPCWSTR lpSubKey,
        LPCWSTR lpValueName
    );
    static LSTATUS WINAPI MyRegDeleteValueA(
        HKEY   hKey,
        LPCSTR lpValueName
    );
    static LSTATUS WINAPI MyRegDeleteValueW(
        HKEY   hKey,
        LPCWSTR lpValueName
    );
    static LSTATUS WINAPI MyRegGetValueA(
        HKEY    hKey,
        LPCSTR  lpSubKey,
        LPCSTR  lpValue,
        DWORD   dwFlags,
        LPDWORD pdwType,
        PVOID   pvData,
        LPDWORD pcbData
    );
    static LSTATUS WINAPI MyRegGetValueW(
        HKEY    hKey,
        LPCWSTR  lpSubKey,
        LPCWSTR  lpValue,
        DWORD   dwFlags,
        LPDWORD pdwType,
        PVOID   pvData,
        LPDWORD pcbData
    );
    static LSTATUS WINAPI MyRegQueryValueA(
        HKEY   hKey,
        LPCSTR lpSubKey,
        LPSTR  lpData,
        PLONG  lpcbData
    );
    static LSTATUS WINAPI MyRegQueryValueW(
        HKEY   hKey,
        LPCWSTR lpSubKey,
        LPWSTR  lpData,
        PLONG  lpcbData
    );
    static LSTATUS WINAPI RegQueryValueExA(
        HKEY    hKey,
        LPCSTR  lpValueName,
        LPDWORD lpReserved,
        LPDWORD lpType,
        LPBYTE  lpData,
        LPDWORD lpcbData
    );
    static LSTATUS WINAPI RegQueryValueExW(
        HKEY    hKey,
        LPCWSTR  lpValueName,
        LPDWORD lpReserved,
        LPDWORD lpType,
        LPBYTE  lpData,
        LPDWORD lpcbData
    );
    static LSTATUS WINAPI MyRegSetValueA(
        HKEY   hKey,
        LPCSTR lpSubKey,
        DWORD  dwType,
        LPCSTR lpData,
        DWORD  cbData
    );
    static LSTATUS WINAPI MyRegSetValueW(
        HKEY   hKey,
        LPCWSTR lpSubKey,
        DWORD  dwType,
        LPCWSTR lpData,
        DWORD  cbData
    );
    static LSTATUS WINAPI MyRegSetValueExA(
        HKEY       hKey,
        LPCSTR     lpValueName,
        DWORD      Reserved,
        DWORD      dwType,
        const BYTE* lpData,
        DWORD      cbData
    );
    static LSTATUS WINAPI MyRegSetValueExW(
        HKEY       hKey,
        LPCWSTR     lpValueName,
        DWORD      Reserved,
        DWORD      dwType,
        const BYTE* lpData,
        DWORD      cbData
    );
    static void InitRegApi();


};
std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> MyRegApi::RegTime;
std::wstring_convert<std::codecvt_utf8<wchar_t>> MyRegApi::WC;
SOCKET MyRegApi::RegSocket;
SOCKADDR_IN MyRegApi::RegServer;
Message* MyRegApi::RegMessage;
std::wstringstream MyRegApi::RegBuffer;

HOOK_TRACE_INFO MyRegApi::RegCloseKeyHook;
HOOK_TRACE_INFO MyRegApi::RegCreateKeyAHook;
HOOK_TRACE_INFO MyRegApi::RegCreateKeyWHook;
HOOK_TRACE_INFO MyRegApi::RegCreateKeyExAHook;
HOOK_TRACE_INFO MyRegApi::RegCreateKeyExWHook;
HOOK_TRACE_INFO MyRegApi::RegDeleteKeyAHook;
HOOK_TRACE_INFO MyRegApi::RegDeleteKeyWHook;
HOOK_TRACE_INFO MyRegApi::RegDeleteKeyExAHook;
HOOK_TRACE_INFO MyRegApi::RegDeleteKeyExWHook;
HOOK_TRACE_INFO MyRegApi::RegDeleteKeyValueAHook;
HOOK_TRACE_INFO MyRegApi::RegDeleteKeyValueWHook;
HOOK_TRACE_INFO MyRegApi::RegDeleteValueAHook;
HOOK_TRACE_INFO MyRegApi::RegDeleteValueWHook;
HOOK_TRACE_INFO MyRegApi::RegGetValueAHook;
HOOK_TRACE_INFO MyRegApi::RegGetValueWHook;
HOOK_TRACE_INFO MyRegApi::RegOpenKeyAHook;
HOOK_TRACE_INFO MyRegApi::RegOpenKeyExAHook;
HOOK_TRACE_INFO MyRegApi::RegOpenKeyWHook;
HOOK_TRACE_INFO MyRegApi::RegOpenKeyExWHook;
HOOK_TRACE_INFO MyRegApi::RegQueryValueAHook;
HOOK_TRACE_INFO MyRegApi::RegQueryValueWHook;
HOOK_TRACE_INFO MyRegApi::RegSetValueAHook;
HOOK_TRACE_INFO MyRegApi::RegSetValueWHook;
HOOK_TRACE_INFO MyRegApi::RegSetValueExAHook;
HOOK_TRACE_INFO MyRegApi::RegSetValueExWHook;
Level MyRegApi::Lv = Debug;
map<HKEY, wstring> MyRegApi::RegMap;

inline std::wstring MyRegApi::GetName(HKEY hKey)
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

LSTATUS WINAPI MyRegApi::MyRegCloseKey(
    HKEY hKey
)
{
    NTSTATUS rtn = RegCloseKey(hKey);
    if ((rtn == ERROR_SUCCESS) && (RegMap.find(hKey) != RegMap.end()))
        RegMap.erase(hKey);
    if (Lv > Extra)
    {
        PLOGD << "RegCloseKey->hKey:" << reinterpret_cast<LONG>(hKey) << endl;
        RegBuffer << "RegCloseKey->hKey:" << reinterpret_cast<LONG>(hKey) << L"\n";
        UdpSend();
    }
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegOpenKeyA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    PHKEY  phkResult
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegOpenKeyA(hKey, lpSubKey, phkResult);
    if (Lv > Extra)
    {
        PLOGD << "RegOpenKeyA->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << endl;
        RegBuffer << "RegOpenKeyA->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << L"\n";
        UdpSend();
    }
        
    if ( (lpSubKey != NULL) && (rtn == ERROR_SUCCESS) )
        RegMap[*phkResult] = tmp + L"\\" + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpSubKey);
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegOpenKeyW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    PHKEY  phkResult
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegOpenKeyW(hKey, lpSubKey, phkResult);
    if (Lv > Extra)
    {
        PLOGD << "RegOpenKeyW->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << endl;
        RegBuffer<< "RegOpenKeyW->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << L"\n";
        UdpSend();
    }
        
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + lpSubKey;
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegCreateKeyA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    PHKEY  phkResult
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegCreateKeyA(hKey, lpSubKey, phkResult);
    if (Lv > Extra)
    {
        PLOGD << "RegCreateKeyA->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << endl;
        RegBuffer << "RegCreateKeyA->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << L"\n";
        UdpSend();
    }
        
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpSubKey);
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegCreateKeyW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    PHKEY  phkResult
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegCreateKeyW(hKey, lpSubKey, phkResult);
    if (Lv > Extra)
    {
        PLOGD << "RegCreateKeyW->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << endl;
        RegBuffer << "RegCreateKeyW->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << L"\n";
        UdpSend();
    }
        
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + lpSubKey;
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegCreateKeyExA(
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
    if (Lv > Extra)
    {
        PLOGD << "RegCreateKeyExA->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << endl;
        RegBuffer << "RegCreateKeyExA->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << L"\n";
        UdpSend();
    }
        
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpSubKey);
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegCreateKeyExW(
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
    if (Lv > Extra)
    {
        PLOGD << "RegCreateKeyExW->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << endl;
        RegBuffer << "RegCreateKeyExW->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << L"\n";
        UdpSend();
    }
        
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + lpSubKey;
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegOpenKeyExA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    DWORD  ulOptions,
    REGSAM samDesired,
    PHKEY  phkResult
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    if (Lv > Extra)
    {
        PLOGD << "RegOpenKeyExA->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << endl;
        RegBuffer << "RegOpenKeyExA->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << L"\n";
        UdpSend();
    }
        
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpSubKey);
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegOpenKeyExW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    DWORD  ulOptions,
    REGSAM samDesired,
    PHKEY  phkResult
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    if (Lv > Extra)
    {
        PLOGD << "RegOpenKeyExW->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << endl;
        RegBuffer << "RegOpenKeyExW->Key" << tmp
            << "  ,SubKey:" << sc(lpSubKey)
            << "  ,result:" << *phkResult << L"\n";
        UdpSend();
    }
        
    if ((lpSubKey != NULL) && (rtn == ERROR_SUCCESS))
        RegMap[*phkResult] = tmp + L"\\" + lpSubKey;
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegDeleteKeyA(
    HKEY   hKey,
    LPCSTR lpSubKey
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteKeyA(hKey, lpSubKey);
    if (Lv > None)
    {
        PLOGD << "RegDeleteKeyA->Key" << tmp
            << "  ,SubKey" << sc(lpSubKey) << endl;
        RegBuffer << "RegDeleteKeyA->Key" << tmp
            << "  ,SubKey" << sc(lpSubKey) << "\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegDeleteKeyExA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    REGSAM samDesired,
    DWORD  Reserved
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteKeyExA(hKey, lpSubKey, samDesired, Reserved);
    if (Lv > None)
    {
        PLOGD << "RegDeleteKeyExA->Key" << tmp
            << "  ,SubKey" << sc(lpSubKey) << endl;
        RegBuffer << "RegDeleteKeyExA->Key" << tmp
            << "  ,SubKey" << sc(lpSubKey) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegDeleteKeyW(
    HKEY   hKey,
    LPCWSTR lpSubKey
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteKeyW(hKey, lpSubKey);
    if (Lv > None)
    {
        PLOGD << "RegDeleteKeyW->Key" << tmp
            << "  ,SubKey" << sc(lpSubKey) << endl;
        RegBuffer << "RegDeleteKeyW->Key" << tmp
            << "  ,SubKey" << sc(lpSubKey) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegDeleteKeyExW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    REGSAM samDesired,
    DWORD  Reserved
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteKeyExW(hKey, lpSubKey, samDesired, Reserved);
    if (Lv > None)
    {
        PLOGD << "RegDeleteKeyExW->Key" << tmp
            << "  ,SubKey" << sc(lpSubKey) << endl;
        RegBuffer << "RegDeleteKeyExW->Key" << tmp
            << "  ,SubKey" << sc(lpSubKey) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegDeleteKeyValueA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    LPCSTR lpValueName
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteKeyValueA(hKey, lpSubKey, lpValueName);
    if (Lv > None)
    {
        PLOGD << "RegDeleteKeyValueA->Key" << tmp
            << "  ,SubKey" << sc(lpSubKey)
            << "  ,ValueName" << sc(lpValueName) << endl;
        RegBuffer << "RegDeleteKeyValueA->Key" << tmp
            << "  ,SubKey" << sc(lpSubKey)
            << "  ,ValueName" << sc(lpValueName) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegDeleteKeyValueW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    LPCWSTR lpValueName
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteKeyValueW(hKey, lpSubKey, lpValueName);
    if (Lv > None)
    {
        PLOGD << "RegDeleteKeyValueA->Key" << tmp
            << "  ,SubKey" << sc(lpSubKey)
            << "  ,ValueName" << sc(lpValueName) << endl;
        RegBuffer << "RegDeleteKeyValueA->Key" << tmp
            << "  ,SubKey" << sc(lpSubKey)
            << "  ,ValueName" << sc(lpValueName) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegDeleteValueA(
    HKEY   hKey,
    LPCSTR lpValueName
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteValueA(hKey, lpValueName);
    if (Lv > None)
    {
        PLOGD << "RegDeleteKeyValueA->Key" << tmp
            << "  ,ValueName" << sc(lpValueName) << endl;
        RegBuffer << "RegDeleteKeyValueA->Key" << tmp
            << "  ,ValueName" << sc(lpValueName) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegDeleteValueW(
    HKEY   hKey,
    LPCWSTR lpValueName
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegDeleteValueW(hKey, lpValueName);
    if (Lv > None)
    {
        PLOGD << "RegDeleteKeyValueA->Key" << tmp
            << "  ,ValueName" << sc(lpValueName) << endl;
        RegBuffer << "RegDeleteKeyValueA->Key" << tmp
            << "  ,ValueName" << sc(lpValueName) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegGetValueA(
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
    if (Lv > Critial)
    {
        PLOGD << "RegGetVlueA->Key:" << tmp
            << "  ,SbuKey" << sc(lpSubKey)
            << "  ,Value:" << sc(lpValue) << endl;
        RegBuffer << "RegGetVlueA->Key:" << tmp
            << "  ,SbuKey" << sc(lpSubKey)
            << "  ,Value:" << sc(lpValue) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegGetValueW(
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
    if (Lv > Critial)
    {
        PLOGD << "RegGetVlueA->Key:" << tmp
            << "  ,SbuKey" << sc(lpSubKey)
            << "  ,Value:" << sc(lpValue) << endl;
        RegBuffer << "RegGetVlueA->Key:" << tmp
            << "  ,SbuKey" << sc(lpSubKey)
            << "  ,Value:" << sc(lpValue) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegQueryValueA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    LPSTR  lpData,
    PLONG  lpcbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegQueryValueA(hKey, lpSubKey, lpData, lpcbData);
    if (Lv > Critial)
    {
        PLOGD << "RegQueryValueA->Key:" << tmp
            << "  ,SubKey" << sc(lpSubKey) << endl;
        RegBuffer << "RegQueryValueA->Key:" << tmp
            << "  ,SubKey" << sc(lpSubKey) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegQueryValueW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    LPWSTR  lpData,
    PLONG  lpcbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegQueryValueW(hKey, lpSubKey, lpData, lpcbData);
    if (Lv > Critial)
    {
        PLOGD << "RegQueryValueW->Key:" << tmp
            << "  ,SubKey" << sc(lpSubKey) << endl;
        RegBuffer << "RegQueryValueW->Key:" << tmp
            << "  ,SubKey" << sc(lpSubKey) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::RegQueryValueExA(
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
    if (Lv > Critial)
    {
        PLOGD << "RegQueryValueExA->Key:" << tmp
            << "  ,Value" << sc(lpValueName) << endl;
        RegBuffer << "RegQueryValueExA->Key:" << tmp
            << "  ,Value" << sc(lpValueName) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::RegQueryValueExW(
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
    if (Lv > Critial)
    {
        PLOGD << "RegQueryValueExW->Key:" << tmp
            << "  ,Value" << sc(lpValueName) << endl;
        RegBuffer << "RegQueryValueExW->Key:" << tmp
            << "  ,Value" << sc(lpValueName) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegSetValueA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    DWORD  dwType,
    LPCSTR lpData,
    DWORD  cbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegSetValueA(hKey, lpSubKey, dwType, lpData, cbData);
    if (Lv > None)
    {
        PLOGD << "RegSetValueA->Key:" << tmp
            << "  ,Subkey:" << sc(lpSubKey)
            << "  ,Data:" << sc(lpData) << endl;
        RegBuffer << "RegSetValueA->Key:" << tmp
            << "  ,Subkey:" << sc(lpSubKey)
            << "  ,Data:" << sc(lpData) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegSetValueW(
    HKEY   hKey,
    LPCWSTR lpSubKey,
    DWORD  dwType,
    LPCWSTR lpData,
    DWORD  cbData
)
{
    wstring tmp = GetName(hKey);
    LSTATUS rtn = RegSetValueW(hKey, lpSubKey, dwType, lpData, cbData);
    if (Lv > None)
    {
        PLOGD << "RegSetValueW->Key:" << tmp
            << "  ,Subkey:" << sc(lpSubKey)
            << "  ,Data:" << sc(lpData) << endl;
        RegBuffer << "RegSetValueW->Key:" << tmp
            << "  ,Subkey:" << sc(lpSubKey)
            << "  ,Data:" << sc(lpData) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegSetValueExA(
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
    if (Lv > None)
    {
        PLOGD << "RegSetValueA->Key:" << tmp
            << "  ,ValueName:" << sc(lpValueName) << endl;
        RegBuffer << "RegSetValueA->Key:" << tmp
            << "  ,ValueName:" << sc(lpValueName) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

LSTATUS WINAPI MyRegApi::MyRegSetValueExW(
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
    if (Lv > None)
    {
        PLOGD << "RegSetValueW->Key:" << tmp
            << "  ,ValueName:" << sc(lpValueName) << endl;
        RegBuffer << "RegSetValueW->Key:" << tmp
            << "  ,ValueName:" << sc(lpValueName) << L"\n";
        UdpSend();
    }
        
    return rtn;
}

inline void MyRegApi::UdpSend()
{
    if (UdpEnable)
    {
        const std::wstring& ws = RegBuffer.str();
        if (ws.size() == 0)
            return;
        else if (ws.size() < 30000 && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - RegTime).count() < 500)
            return;
        else if (WProcName.size() > 500 || ws.size() > 50000)
            PLOGE << "Data too long\n";
        else
        {
            memset(RegMessage, 0, sizeof(Message));
            RegMessage->type = 2;
            memcpy(RegMessage->Processname, WC.to_bytes(WProcName).c_str(), WProcName.size());
            memcpy(RegMessage->Data, WC.to_bytes(ws).c_str(), ws.size());
            if (sendto(RegSocket, (char*)RegMessage, sizeof(Message), 0, (SOCKADDR*)&RegServer, sizeof(SOCKADDR)) == SOCKET_ERROR)
                PLOGE << RtlGetLastErrorString() << std::endl;
            else
                RegBuffer.str(L"");
            RegTime = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
        }
    }
    else
        RegBuffer.str(L"");
    return;
}


void MyRegApi::InitRegApi()
{
    Check("RegCloseKey", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegCloseKey"), MyRegApi::MyRegCloseKey, NULL, &MyRegApi::RegCloseKeyHook));
    Check("RegCreateKeyA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegCreateKeyA"), MyRegApi::MyRegCreateKeyA, NULL, &MyRegApi::RegCreateKeyAHook));
    Check("RegCreateKeyW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegCreateKeyW"), MyRegApi::MyRegCreateKeyW, NULL, &MyRegApi::RegCreateKeyWHook));
    Check("RegCreateKeyExA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegCreateKeyExA"), MyRegApi::MyRegCreateKeyExA, NULL, &MyRegApi::RegCreateKeyExAHook));
    Check("RegCreateKeyExW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegCreateKeyExW"), MyRegApi::MyRegCreateKeyExW, NULL, &MyRegApi::RegCreateKeyExWHook));
    Check("RegDeleteKeyA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteKeyA"), MyRegApi::MyRegDeleteKeyA, NULL, &MyRegApi::RegDeleteKeyAHook));
    Check("RegDeleteKeyW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteKeyW"), MyRegApi::MyRegDeleteKeyW, NULL, &MyRegApi::RegDeleteKeyWHook));
    Check("RegDeleteKeyExA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteKeyExA"), MyRegApi::MyRegDeleteKeyExA, NULL, &MyRegApi::RegDeleteKeyExAHook));
    Check("RegDeleteKeyExW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteKeyExW"), MyRegApi::MyRegDeleteKeyExW, NULL, &MyRegApi::RegDeleteKeyExWHook));
    Check("RegDeleteKeyValueA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteKeyValueA"), MyRegApi::MyRegDeleteKeyValueA, NULL, &MyRegApi::RegDeleteKeyValueAHook));
    Check("RegDeleteKeyValueW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteKeyValueW"), MyRegApi::MyRegDeleteKeyValueW, NULL, &MyRegApi::RegDeleteKeyValueWHook));
    Check("RegDeleteValueA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteValueA"), MyRegApi::MyRegDeleteValueA, NULL, &MyRegApi::RegDeleteValueAHook));
    Check("RegDeleteValueW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegDeleteValueW"), MyRegApi::MyRegDeleteValueW, NULL, &MyRegApi::RegDeleteValueWHook));
    Check("RegGetValueW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegGetValueW"), MyRegApi::MyRegGetValueW, NULL, &MyRegApi::RegGetValueWHook));
    Check("RegGetValueA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegGetValueA"), MyRegApi::MyRegGetValueA, NULL, &MyRegApi::RegGetValueAHook));
    Check("RegOpenKeyA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegOpenKeyA"), MyRegApi::MyRegOpenKeyA, NULL, &MyRegApi::RegOpenKeyAHook));
    Check("RegOpenKeyW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegOpenKeyW"), MyRegApi::MyRegOpenKeyW, NULL, &MyRegApi::RegOpenKeyWHook));
    Check("RegOpenKeyExW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegOpenKeyExW"), MyRegApi::MyRegOpenKeyExW, NULL, &MyRegApi::RegOpenKeyExWHook));
    Check("RegOpenKeyExA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegOpenKeyExA"), MyRegApi::MyRegOpenKeyExA, NULL, &MyRegApi::RegOpenKeyExAHook));
    Check("RegQueryValueA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegQueryValueA"), MyRegApi::MyRegQueryValueA, NULL, &MyRegApi::RegQueryValueAHook));
    Check("RegQueryValueW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegQueryValueW"), MyRegApi::MyRegQueryValueW, NULL, &MyRegApi::RegQueryValueWHook));
    Check("RegSetValueA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegSetValueA"), MyRegApi::MyRegSetValueA, NULL, &MyRegApi::RegSetValueAHook));
    Check("RegSetValueW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegSetValueW"), MyRegApi::MyRegSetValueW, NULL, &MyRegApi::RegSetValueWHook));
    Check("RegSetValueExW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegSetValueExW"), MyRegApi::MyRegSetValueExW, NULL, &MyRegApi::RegSetValueExWHook));
    Check("RegSetValueExA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegSetValueExA"), MyRegApi::MyRegSetValueExA, NULL, &MyRegApi::RegSetValueExAHook));



    ULONG ACLEntries[1] = { 0 };

    Check("RegCloseKey", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegCloseKeyHook));
    Check("RegCreateKeyA", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegCreateKeyAHook));
    Check("RegCreateKeyW", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegCreateKeyWHook));
    Check("RegCreateKeyExA", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegCreateKeyExAHook));
    Check("RegCreateKeyExW", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegCreateKeyExWHook));
    Check("RegDeleteKeyA", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegDeleteKeyAHook));
    Check("RegDeleteKeyW", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegDeleteKeyWHook));
    Check("RegDeleteKeyExA", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegDeleteKeyExAHook));
    Check("RegDeleteKeyExW", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegDeleteKeyExWHook));
    Check("RegDeleteKeyValueA", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegDeleteKeyValueAHook));
    Check("RegDeleteKeyValueW", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegDeleteKeyValueWHook));
    Check("RegDeleteValueA", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegDeleteValueAHook));
    Check("RegDeleteValueW", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegDeleteValueWHook));
    Check("RegGetValueW", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegGetValueWHook));
    Check("RegGetValueA", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegGetValueAHook));
    Check("RegOpenKeyA", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegOpenKeyAHook));
    Check("RegOpenKeyW", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegOpenKeyWHook));
    Check("RegOpenKeyExW", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegOpenKeyExWHook));
    Check("RegOpenKeyExA", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegOpenKeyExAHook));
    Check("RegQueryValueA", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegQueryValueAHook));
    Check("RegQueryValueW", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegQueryValueWHook));
    Check("RegSetValueA", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegSetValueAHook));
    Check("RegSetValueW", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegSetValueWHook));
    Check("RegSetValueExW", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegSetValueExWHook));
    Check("RegSetValueExA", LhSetExclusiveACL(ACLEntries, 1, &MyRegApi::RegSetValueExAHook));

    if (SOCKET_ERROR == (RegSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)))
        PLOGE << "Init socket error" << endl;
    RegServer.sin_family = AF_INET;
    RegServer.sin_addr.s_addr = inet_addr(ServerAddr.c_str());
    RegServer.sin_port = htons(port);
    RegMessage = new Message;
    RegTime = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
}