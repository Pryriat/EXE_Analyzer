#pragma once
#include"Global.h"
#include<wininet.h>
#pragma  comment(lib,"Wininet.lib")
using std::map;
using std::wstring;
using std::endl;

BOOL WinNetApiEnable = TRUE;

map<HANDLE, wstring> InternetOpenHandleMap;
map<HANDLE, wstring> InternetFileHandleMap;
map<HANDLE, wstring> FtpSessionMap;
map<HANDLE, wstring> HttpSessionMap;
map<HANDLE, wstring>HttpRequestMap;

HOOK_TRACE_INFO InternetOpenAHook;
HOOK_TRACE_INFO InternetOpenWHook;
HOOK_TRACE_INFO InternetOpenUrlAHook;
HOOK_TRACE_INFO InternetOpenUrlWHook;
HOOK_TRACE_INFO InternetConnectAHook;
HOOK_TRACE_INFO InternetConnectWHook;
HOOK_TRACE_INFO InternetReadFileHook;
HOOK_TRACE_INFO InternetReadFileExAHook;
HOOK_TRACE_INFO InternetReadFileExWHook;
HOOK_TRACE_INFO InternetWriteFileHook;
HOOK_TRACE_INFO HttpOpenRequestAHook;
HOOK_TRACE_INFO HttpOpenRequestWHook;
HOOK_TRACE_INFO HttpSendRequestAHook;
HOOK_TRACE_INFO HttpSendRequestWHook;
HOOK_TRACE_INFO HttpSendRequestExAHook;
HOOK_TRACE_INFO HttpSendRequestExWHook;


HINTERNET WINAPI MyInternetOpenA(
    LPCSTR lpszAgent,
    DWORD  dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD  dwFlags
)
{
    HINTERNET rtn = InternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    if (rtn != NULL)
    {
        InternetOpenHandleMap[rtn] = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sc(lpszAgent));
        PLOGD << "InternetOpenA->Agent:" << sc(lpszAgent)
            << "  ,Proxy:" << sc(lpszProxy)
            << "  ,ProxyByPass" << sc(lpszProxyBypass)
            << "  ,Status:Success" << endl;
    }
    else
        PLOGD << "InternetOpenA->Agent:" << sc(lpszAgent)
        << "  ,Proxy:" << sc(lpszProxy)
        << "  ,ProxyByPass:" << sc(lpszProxyBypass)
        << "  ,Status:Failed:" << endl;
    return rtn;
}

HINTERNET WINAPI MyInternetOpenW(
    LPCWSTR lpszAgent,
    DWORD  dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD  dwFlags
)
{
    HINTERNET rtn = InternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    if (rtn != NULL)
    {
        InternetOpenHandleMap[rtn] = sc(lpszAgent);
        PLOGD << "InternetOpenA->Agent:" << sc(lpszAgent)
            << "  ,Proxy:" << sc(lpszProxy)
            << "  ,ProxyByPass" << sc(lpszProxyBypass)
            << "  ,Status:Success" << endl;
    }
    else
        PLOGD << "InternetOpenA->Agent:" << sc(lpszAgent)
        << "  ,Proxy:" << sc(lpszProxy)
        << "  ,ProxyByPass:" << sc(lpszProxyBypass)
        << "  ,Status:Failed:" << endl;
    return rtn;
}

HINTERNET WINAPI MyInternetOpenUrlA(
    HINTERNET hInternet,
    LPCSTR    lpszUrl,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
)
{
    HINTERNET rtn = InternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
    if (rtn != NULL)
    {
        InternetFileHandleMap[rtn] = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sc(lpszUrl));
        PLOGD << "InternetOpenUrlA->Agent:" << InternetOpenHandleMap[hInternet]
            << "  ,Url:" << sc(lpszUrl)
            << "  ,Headers" << sc(lpszHeaders)
            << "  ,Status:Success" << endl;
    }
    else
        PLOGD << "InternetOpenUrlA->Agent:" << InternetOpenHandleMap[hInternet]
        << "  ,Url:" << sc(lpszUrl)
        << "  ,Headers" << sc(lpszHeaders)
        << "  ,Status:Failed" << endl;
    return rtn;
}

HINTERNET WINAPI MyInternetOpenUrlW(
    HINTERNET hInternet,
    LPCWSTR    lpszUrl,
    LPCWSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
)
{
    HINTERNET rtn = InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
    if (rtn != NULL)
    {
        InternetFileHandleMap[rtn] = sc(lpszUrl);
        PLOGD << "InternetOpenUrlA->Agent:" << InternetOpenHandleMap[hInternet]
            << "  ,Url:" << sc(lpszUrl)
            << "  ,Headers" << sc(lpszHeaders)
            << "  ,Status:Success" << endl;
    }
    else
        PLOGD << "InternetOpenUrlA->Agent:" << InternetOpenHandleMap[hInternet]
        << "  ,Url:" << sc(lpszUrl)
        << "  ,Headers" << sc(lpszHeaders)
        << "  ,Status:Failed" << endl;
    return rtn;
}

HINTERNET WINAPI  MyInternetConnectA(
    HINTERNET     hInternet,
    LPCSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR        lpszUserName,
    LPCSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
)
{
    HINTERNET rtn = InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    if (rtn != NULL)
    {
        switch (dwService)
        {
        case INTERNET_SERVICE_FTP:
            FtpSessionMap[rtn] = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpszServerName);
            PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Server:" << sc(lpszServerName)
                << "  ,ServerPort:" << nServerPort
                << "  ,UserName:" << sc(lpszUserName)
                << "  ,Password:" << sc(lpszPassword)
                << " ServiceType:FTP  ,Status:Success" << endl;
            break;
        case INTERNET_SERVICE_HTTP:
            HttpSessionMap[rtn] = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpszServerName);
            PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Server:" << sc(lpszServerName)
                << "  ,ServerPort:" << nServerPort
                << "  ,UserName:" << sc(lpszUserName)
                << "  ,Password:" << sc(lpszPassword)
                << " ServiceType:HTTP  ,Status:Success" << endl;
        default:
            PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Server:" << sc(lpszServerName)
                << "  ,ServerPort:" << nServerPort
                << "  ,UserName:" << sc(lpszUserName)
                << "  ,Password:" << sc(lpszPassword)
                << " ServiceType:Unknows  ,Status:Success" << endl;
        }
    }
    else
    {
        switch (dwService)
        {
        case INTERNET_SERVICE_FTP:
            PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Server:" << sc(lpszServerName)
                << "  ,ServerPort:" << nServerPort
                << "  ,UserName:" << sc(lpszUserName)
                << "  ,Password:" << sc(lpszPassword)
                << " ServiceType:FTP  ,Status:Failed" << endl;
            break;
        case INTERNET_SERVICE_HTTP:
            PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Server:" << sc(lpszServerName)
                << "  ,ServerPort:" << nServerPort
                << "  ,UserName:" << sc(lpszUserName)
                << "  ,Password:" << sc(lpszPassword)
                << " ServiceType:HTTP  ,Status:Failed" << endl;
        default:
            PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Server:" << sc(lpszServerName)
                << "  ,ServerPort:" << nServerPort
                << "  ,UserName:" << sc(lpszUserName)
                << "  ,Password:" << sc(lpszPassword)
                << " ServiceType:Unknows  ,Status:Failed" << endl;
        }
    }
    return rtn;
}

HINTERNET WINAPI  MyInternetConnectW(
    HINTERNET     hInternet,
    LPCWSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCWSTR        lpszUserName,
    LPCWSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
)
{
    HINTERNET rtn = InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    if (rtn != NULL)
    {
        switch (dwService)
        {
        case INTERNET_SERVICE_FTP:
            FtpSessionMap[rtn] = lpszServerName;
            PLOGD << "InternetOpenW->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Server:" << sc(lpszServerName)
                << "  ,ServerPort:" << nServerPort
                << "  ,UserName:" << sc(lpszUserName)
                << "  ,Password:" << sc(lpszPassword)
                << " ServiceType:FTP  ,Status:Success" << endl;
            break;
        case INTERNET_SERVICE_HTTP:
            HttpSessionMap[rtn] = lpszServerName;
            PLOGD << "InternetOpenW->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Server:" << sc(lpszServerName)
                << "  ,ServerPort:" << nServerPort
                << "  ,UserName:" << sc(lpszUserName)
                << "  ,Password:" << sc(lpszPassword)
                << " ServiceType:HTTP  ,Status:Success" << endl;
        default:
            PLOGD << "InternetOpenW->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Server:" << sc(lpszServerName)
                << "  ,ServerPort:" << nServerPort
                << "  ,UserName:" << sc(lpszUserName)
                << "  ,Password:" << sc(lpszPassword)
                << " ServiceType:Unknows  ,Status:Success" << endl;
        }
    }
    else
    {
        switch (dwService)
        {
        case INTERNET_SERVICE_FTP:
            PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Server:" << sc(lpszServerName)
                << "  ,ServerPort:" << nServerPort
                << "  ,UserName:" << sc(lpszUserName)
                << "  ,Password:" << sc(lpszPassword)
                << " ServiceType:FTP  ,Status:Failed" << endl;
            break;
        case INTERNET_SERVICE_HTTP:
            PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Server:" << sc(lpszServerName)
                << "  ,ServerPort:" << nServerPort
                << "  ,UserName:" << sc(lpszUserName)
                << "  ,Password:" << sc(lpszPassword)
                << " ServiceType:HTTP  ,Status:Failed" << endl;
        default:
            PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Server:" << sc(lpszServerName)
                << "  ,ServerPort:" << nServerPort
                << "  ,UserName:" << sc(lpszUserName)
                << "  ,Password:" << sc(lpszPassword)
                << " ServiceType:Unknows  ,Status:Failed" << endl;
        }
    }
    return rtn;
}

BOOL WINAPI MyInternetReadFile(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
)
{
    BOOL rtn = InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    PLOGD << "InternetReadFile->FileName:" << InternetFileHandleMap[hFile]
        << "  ,NumberOfBytesRead:" << *lpdwNumberOfBytesRead 
        <<"  ,Status:"<<rtn<< endl;
    return rtn;
}

BOOL WINAPI MyInternetReadFileExA(
    HINTERNET           hFile,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
)
{
    BOOL rtn = InternetReadFileExA(hFile, lpBuffersOut, dwFlags, dwContext);
    PLOGD << "InternetReadFileExA->FileName:" << InternetFileHandleMap[hFile]
        << "  ,Status:" << rtn << endl;
    return rtn;
}

BOOL WINAPI MyInternetReadFileExW(
    HINTERNET           hFile,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
)
{
    BOOL rtn = InternetReadFileExW(hFile, lpBuffersOut, dwFlags, dwContext);
    PLOGD << "InternetReadFileExW->FileName:" << InternetFileHandleMap[hFile]
        << "  ,Status:" << rtn << endl;
    return rtn;
}

BOOL WINAPI MyInternetWriteFile(
    HINTERNET hFile,
    LPCVOID   lpBuffer,
    DWORD     dwNumberOfBytesToWrite,
    LPDWORD   lpdwNumberOfBytesWritten
)
{
    BOOL rtn = InternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
    PLOGD << "InternetWriteFile->FileName:" << InternetFileHandleMap[hFile]
        << "  ,NumberOfBytesWritten:" << *lpdwNumberOfBytesWritten
        << "  ,Status:" << rtn << endl;
    return rtn;
}

HINTERNET WINAPI MyHttpOpenRequestA(
    HINTERNET hConnect,
    LPCSTR    lpszVerb,
    LPCSTR    lpszObjectName,
    LPCSTR    lpszVersion,
    LPCSTR    lpszReferrer,
    LPCSTR* lplpszAcceptTypes,
    DWORD     dwFlags,
    DWORD_PTR dwContext
)
{
    HINTERNET rtn = HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    if (rtn)
    {
        InternetFileHandleMap[rtn] = HttpSessionMap[hConnect] + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sc(lpszObjectName));
        PLOGD << "HttpOpenRequestA->Server:" << HttpSessionMap[hConnect]
            << "  ,Method:" << ((lpszVerb == NULL) ? "Get" : sc(lpszVerb))
            << "  ,Target:" << sc(lpszObjectName)
            << "  ,Referrer:" << sc(lpszReferrer) << endl;;
    }
    return rtn;
}

HINTERNET WINAPI MyHttpOpenRequestW(
    HINTERNET hConnect,
    LPCWSTR    lpszVerb,
    LPCWSTR    lpszObjectName,
    LPCWSTR    lpszVersion,
    LPCWSTR    lpszReferrer,
    LPCWSTR* lplpszAcceptTypes,
    DWORD     dwFlags,
    DWORD_PTR dwContext
)
{
    HINTERNET rtn = HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    if (rtn)
    {
        InternetFileHandleMap[rtn] = HttpSessionMap[hConnect] + sc(lpszObjectName);
        PLOGD << "HttpOpenRequestW->Server:" << HttpSessionMap[hConnect]
            << "  ,Method:" << (lpszVerb == NULL ? L"Get" : sc(lpszVerb))
            << "  ,Target:" << sc(lpszObjectName)
            << "  ,Referrer:" << sc(lpszReferrer) << endl;
    }
    return rtn;
}

BOOL WINAPI MyHttpSendRequestA(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
)
{
    BOOL rtn = HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    PLOGD << "HttpSendRequest->RequestTarget:" << InternetFileHandleMap[hRequest]
        << "  ,Headers:" << sc(lpszHeaders)
        << "  Status:" << rtn << endl;
    return rtn;
}

BOOL WINAPI MyHttpSendRequestW(
    HINTERNET hRequest,
    LPCWSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
)
{
    BOOL rtn = HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    PLOGD << "HttpSendRequest->RequestTarget:" << InternetFileHandleMap[hRequest]
        << "  ,Headers:" << sc(lpszHeaders)
        << "  Status:" << rtn << endl;
    return rtn;
}

BOOL WINAPI MyHttpSendRequestExA(
    HINTERNET           hRequest,
    LPINTERNET_BUFFERSA lpBuffersIn,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
)
{
    BOOL rtn = HttpSendRequestExA(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);
    PLOGD << "HttpSendRequest->RequestTarget:" << InternetFileHandleMap[hRequest]
        << "  Status:" << rtn << endl;
    return rtn;
}

BOOL WINAPI MyHttpSendRequestExW(
    HINTERNET           hRequest,
    LPINTERNET_BUFFERSW lpBuffersIn,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
)
{
    BOOL rtn = HttpSendRequestExW(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);
    PLOGD << "HttpSendRequest->RequestTarget:" << InternetFileHandleMap[hRequest]
        << "  Status:" << rtn << endl;
    return rtn;
}


void InitWinNetApi64()
{
    Check("InternetOpenA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetOpenA"), MyInternetOpenA, NULL, &InternetOpenAHook));
    Check("InternetOpenW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetOpenW"), MyInternetOpenW, NULL, &InternetOpenWHook));
    Check("InternetConnectA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetConnectA"), MyInternetConnectA, NULL, &InternetConnectAHook));
    Check("InternetConnectW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetConnectW"), MyInternetConnectW, NULL, &InternetConnectWHook));
    Check("InternetOpenUrlA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetOpenUrlA"), MyInternetOpenUrlA, NULL, &InternetOpenUrlAHook));
    Check("InternetOpenUrlW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetOpenUrlW"), MyInternetOpenUrlW, NULL, &InternetOpenUrlWHook));
    Check("InternetReadFile",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetReadFile"), MyInternetReadFile, NULL, &InternetReadFileHook));
    Check("InternetReadFileExA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetReadFileExA"), MyInternetReadFileExA, NULL, &InternetReadFileExAHook));
    Check("InternetReadFileExW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetReadFileExW"), MyInternetReadFileExW, NULL, &InternetReadFileExWHook));
    Check("InternetWriteFile",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetWriteFile"), MyInternetWriteFile, NULL, &InternetWriteFileHook));
    Check("HttpOpenRequestA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "HttpOpenRequestA"), MyHttpOpenRequestA, NULL, &HttpOpenRequestAHook));
    Check("HttpOpenRequestW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "HttpOpenRequestW"), MyHttpOpenRequestW, NULL, &HttpOpenRequestWHook));
    Check("HttpSendRequestA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "HttpSendRequestA"), MyHttpSendRequestA, NULL, &HttpSendRequestAHook));
    Check("HttpSendRequestW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "HttpSendRequestW"), MyHttpSendRequestW, NULL, &HttpSendRequestWHook));
    Check("HttpSendRequestExA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "HttpSendRequestExA"), MyHttpSendRequestExA, NULL, &HttpSendRequestExAHook));
    Check("HttpSendRequestExW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "HttpSendRequestExW"), MyHttpSendRequestExA, NULL, &HttpSendRequestExWHook));

    ULONG ACLEntries[1] = { 0 };
    Check("InternetOpenA",LhSetExclusiveACL(ACLEntries, 1, &InternetOpenAHook));
    Check("InternetOpenW", LhSetExclusiveACL(ACLEntries, 1, &InternetOpenWHook));
    Check("InternetConnectA", LhSetExclusiveACL(ACLEntries, 1, &InternetConnectAHook));
    Check("InternetConnectW", LhSetExclusiveACL(ACLEntries, 1, &InternetConnectWHook));
    Check("InternetOpenUrlA", LhSetExclusiveACL(ACLEntries, 1, &InternetOpenUrlAHook));
    Check("InternetOpenUrlW", LhSetExclusiveACL(ACLEntries, 1, &InternetOpenUrlWHook));
    Check("InternetReadFile", LhSetExclusiveACL(ACLEntries, 1, &InternetReadFileHook));
    Check("InternetReadFileExA", LhSetExclusiveACL(ACLEntries, 1, &InternetReadFileExAHook));
    Check("InternetReadFileExW", LhSetExclusiveACL(ACLEntries, 1, &InternetReadFileExWHook));
    Check("InternetWriteFile", LhSetExclusiveACL(ACLEntries, 1, &InternetWriteFileHook));
    Check("HttpOpenRequestA", LhSetExclusiveACL(ACLEntries, 1, &HttpOpenRequestAHook));
    Check("HttpOpenRequestW", LhSetExclusiveACL(ACLEntries, 1, &HttpOpenRequestWHook));
    Check("HttpSendRequestA", LhSetExclusiveACL(ACLEntries, 1, &HttpSendRequestAHook));
    Check("HttpSendRequestW", LhSetExclusiveACL(ACLEntries, 1, &HttpSendRequestWHook));
    Check("HttpSendRequestExA", LhSetExclusiveACL(ACLEntries, 1, &HttpSendRequestExAHook));
    Check("HttpSendRequestExW", LhSetExclusiveACL(ACLEntries, 1, &HttpSendRequestExWHook));
}

