#pragma once
#include"Global.h"
using std::map;
using std::wstring;
using std::endl;

class MyWinNetApi
{
public:

    static std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> WinNetTime;
    static Level Lv;
    static std::wstring_convert<std::codecvt_utf8<wchar_t>> WC;
    static SOCKET WinNetSocket;
    static SOCKADDR_IN WinNetServer;
    static Message* WinNetMessage;
    static std::wstringstream WinNetBuffer;

    static map<HANDLE, wstring> InternetOpenHandleMap;
    static map<HANDLE, wstring> InternetFileHandleMap;
    static map<HANDLE, wstring> FtpSessionMap;
    static map<HANDLE, wstring> HttpSessionMap;
    static map<HANDLE, wstring> HttpRequestMap;

    static HOOK_TRACE_INFO InternetOpenAHook;
    static HOOK_TRACE_INFO InternetOpenWHook;
    static HOOK_TRACE_INFO InternetOpenUrlAHook;
    static HOOK_TRACE_INFO InternetOpenUrlWHook;
    static HOOK_TRACE_INFO InternetConnectAHook;
    static HOOK_TRACE_INFO InternetConnectWHook;
    static HOOK_TRACE_INFO InternetReadFileHook;
    static HOOK_TRACE_INFO InternetReadFileExAHook;
    static HOOK_TRACE_INFO InternetReadFileExWHook;
    static HOOK_TRACE_INFO InternetWriteFileHook;
    static HOOK_TRACE_INFO HttpOpenRequestAHook;
    static HOOK_TRACE_INFO HttpOpenRequestWHook;
    static HOOK_TRACE_INFO HttpSendRequestAHook;
    static HOOK_TRACE_INFO HttpSendRequestWHook;
    static HOOK_TRACE_INFO HttpSendRequestExAHook;
    static HOOK_TRACE_INFO HttpSendRequestExWHook;
    static void SetLv(Level Lv)
    {
        MyWinNetApi::Lv = Lv;
    }
    static void InitWinNetApi();
    static inline void UdpSend();
    static HINTERNET WINAPI MyInternetOpenA(
        LPCSTR lpszAgent,
        DWORD  dwAccessType,
        LPCSTR lpszProxy,
        LPCSTR lpszProxyBypass,
        DWORD  dwFlags
    );
    static HINTERNET WINAPI MyInternetOpenW(
        LPCWSTR lpszAgent,
        DWORD  dwAccessType,
        LPCWSTR lpszProxy,
        LPCWSTR lpszProxyBypass,
        DWORD  dwFlags
    );
    static HINTERNET WINAPI MyInternetOpenUrlA(
        HINTERNET hInternet,
        LPCSTR    lpszUrl,
        LPCSTR    lpszHeaders,
        DWORD     dwHeadersLength,
        DWORD     dwFlags,
        DWORD_PTR dwContext
    );
    static HINTERNET WINAPI MyInternetOpenUrlW(
        HINTERNET hInternet,
        LPCWSTR    lpszUrl,
        LPCWSTR    lpszHeaders,
        DWORD     dwHeadersLength,
        DWORD     dwFlags,
        DWORD_PTR dwContext
    );
   static HINTERNET WINAPI  MyInternetConnectA(
        HINTERNET     hInternet,
        LPCSTR        lpszServerName,
        INTERNET_PORT nServerPort,
        LPCSTR        lpszUserName,
        LPCSTR        lpszPassword,
        DWORD         dwService,
        DWORD         dwFlags,
        DWORD_PTR     dwContext
    );
   static HINTERNET WINAPI  MyInternetConnectW(
       HINTERNET     hInternet,
       LPCWSTR        lpszServerName,
       INTERNET_PORT nServerPort,
       LPCWSTR        lpszUserName,
       LPCWSTR        lpszPassword,
       DWORD         dwService,
       DWORD         dwFlags,
       DWORD_PTR     dwContext
   );
   static BOOL WINAPI MyInternetReadFile(
       HINTERNET hFile,
       LPVOID    lpBuffer,
       DWORD     dwNumberOfBytesToRead,
       LPDWORD   lpdwNumberOfBytesRead
   );
   static BOOL WINAPI MyInternetReadFileExA(
       HINTERNET           hFile,
       LPINTERNET_BUFFERSA lpBuffersOut,
       DWORD               dwFlags,
       DWORD_PTR           dwContext
   );
   static BOOL WINAPI MyInternetReadFileExW(
       HINTERNET           hFile,
       LPINTERNET_BUFFERSW lpBuffersOut,
       DWORD               dwFlags,
       DWORD_PTR           dwContext
   );
   static BOOL WINAPI MyInternetWriteFile(
       HINTERNET hFile,
       LPCVOID   lpBuffer,
       DWORD     dwNumberOfBytesToWrite,
       LPDWORD   lpdwNumberOfBytesWritten
   );
   static HINTERNET WINAPI MyHttpOpenRequestA(
       HINTERNET hConnect,
       LPCSTR    lpszVerb,
       LPCSTR    lpszObjectName,
       LPCSTR    lpszVersion,
       LPCSTR    lpszReferrer,
       LPCSTR* lplpszAcceptTypes,
       DWORD     dwFlags,
       DWORD_PTR dwContext
   );
   static HINTERNET WINAPI MyHttpOpenRequestW(
       HINTERNET hConnect,
       LPCWSTR    lpszVerb,
       LPCWSTR    lpszObjectName,
       LPCWSTR    lpszVersion,
       LPCWSTR    lpszReferrer,
       LPCWSTR* lplpszAcceptTypes,
       DWORD     dwFlags,
       DWORD_PTR dwContext
   );
   static BOOL WINAPI MyHttpSendRequestA(
       HINTERNET hRequest,
       LPCSTR    lpszHeaders,
       DWORD     dwHeadersLength,
       LPVOID    lpOptional,
       DWORD     dwOptionalLength
   );
   static BOOL WINAPI MyHttpSendRequestW(
       HINTERNET hRequest,
       LPCWSTR    lpszHeaders,
       DWORD     dwHeadersLength,
       LPVOID    lpOptional,
       DWORD     dwOptionalLength
   );
   static BOOL WINAPI MyHttpSendRequestExA(
       HINTERNET           hRequest,
       LPINTERNET_BUFFERSA lpBuffersIn,
       LPINTERNET_BUFFERSA lpBuffersOut,
       DWORD               dwFlags,
       DWORD_PTR           dwContext
   );
   static BOOL WINAPI MyHttpSendRequestExW(
       HINTERNET           hRequest,
       LPINTERNET_BUFFERSW lpBuffersIn,
       LPINTERNET_BUFFERSW lpBuffersOut,
       DWORD               dwFlags,
       DWORD_PTR           dwContext
   );
};
std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> MyWinNetApi::WinNetTime;
std::wstring_convert<std::codecvt_utf8<wchar_t>> MyWinNetApi::WC;
SOCKET MyWinNetApi::WinNetSocket;
SOCKADDR_IN MyWinNetApi::WinNetServer;
Message* MyWinNetApi::WinNetMessage;
std::wstringstream MyWinNetApi::WinNetBuffer;
Level MyWinNetApi::Lv = Debug;
map<HANDLE, wstring> MyWinNetApi::InternetOpenHandleMap;
map<HANDLE, wstring> MyWinNetApi::InternetFileHandleMap;
map<HANDLE, wstring> MyWinNetApi::FtpSessionMap;
map<HANDLE, wstring> MyWinNetApi::HttpSessionMap;
map<HANDLE, wstring> MyWinNetApi::HttpRequestMap;

HOOK_TRACE_INFO MyWinNetApi::InternetOpenAHook;
HOOK_TRACE_INFO MyWinNetApi::InternetOpenWHook;
HOOK_TRACE_INFO MyWinNetApi::InternetOpenUrlAHook;
HOOK_TRACE_INFO MyWinNetApi::InternetOpenUrlWHook;
HOOK_TRACE_INFO MyWinNetApi::InternetConnectAHook;
HOOK_TRACE_INFO MyWinNetApi::InternetConnectWHook;
HOOK_TRACE_INFO MyWinNetApi::InternetReadFileHook;
HOOK_TRACE_INFO MyWinNetApi::InternetReadFileExAHook;
HOOK_TRACE_INFO MyWinNetApi::InternetReadFileExWHook;
HOOK_TRACE_INFO MyWinNetApi::InternetWriteFileHook;
HOOK_TRACE_INFO MyWinNetApi::HttpOpenRequestAHook;
HOOK_TRACE_INFO MyWinNetApi::HttpOpenRequestWHook;
HOOK_TRACE_INFO MyWinNetApi::HttpSendRequestAHook;
HOOK_TRACE_INFO MyWinNetApi::HttpSendRequestWHook;
HOOK_TRACE_INFO MyWinNetApi::HttpSendRequestExAHook;
HOOK_TRACE_INFO MyWinNetApi::HttpSendRequestExWHook;



HINTERNET WINAPI MyWinNetApi::MyInternetOpenA(
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
        if (Lv > Extra)
        {
            PLOGD << "InternetOpenA->Agent:" << sc(lpszAgent)
                << "  ,Proxy:" << sc(lpszProxy)
                << "  ,ProxyByPass" << sc(lpszProxyBypass)
                << "  ,Status:Success" << endl;
            WinNetBuffer << "InternetOpenA->Agent:" << sc(lpszAgent)
                << "  ,Proxy:" << sc(lpszProxy)
                << "  ,ProxyByPass" << sc(lpszProxyBypass)
                << "  ,Status:Success" << L"\n";
            UdpSend();
        }
            
    }
    else if (Lv > Extra)
    {
        PLOGD << "InternetOpenA->Agent:" << sc(lpszAgent)
            << "  ,Proxy:" << sc(lpszProxy)
            << "  ,ProxyByPass:" << sc(lpszProxyBypass)
            << "  ,Status:Failed:" << endl;
        WinNetBuffer << "InternetOpenA->Agent:" << sc(lpszAgent)
            << "  ,Proxy:" << sc(lpszProxy)
            << "  ,ProxyByPass:" << sc(lpszProxyBypass)
            << "  ,Status:Failed:" << L"\n";
        UdpSend();
    }
        
    return rtn;
}

HINTERNET WINAPI MyWinNetApi::MyInternetOpenW(
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
        if (Lv > Extra)
        {
            PLOGD << "InternetOpenA->Agent:" << sc(lpszAgent)
                << "  ,Proxy:" << sc(lpszProxy)
                << "  ,ProxyByPass" << sc(lpszProxyBypass)
                << "  ,Status:Success" << endl;
            WinNetBuffer << "InternetOpenA->Agent:" << sc(lpszAgent)
                << "  ,Proxy:" << sc(lpszProxy)
                << "  ,ProxyByPass" << sc(lpszProxyBypass)
                << "  ,Status:Success" << L"\n";
            UdpSend();
        }
            
    }
    else if (Lv > Extra)
    {
        PLOGD << "InternetOpenA->Agent:" << sc(lpszAgent)
            << "  ,Proxy:" << sc(lpszProxy)
            << "  ,ProxyByPass:" << sc(lpszProxyBypass)
            << "  ,Status:Failed:" << endl;
        WinNetBuffer << "InternetOpenA->Agent:" << sc(lpszAgent)
            << "  ,Proxy:" << sc(lpszProxy)
            << "  ,ProxyByPass:" << sc(lpszProxyBypass)
            << "  ,Status:Failed:" << L"\n";
        UdpSend();
    }
        
    return rtn;
}

HINTERNET WINAPI MyWinNetApi::MyInternetOpenUrlA(
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
        if (Lv > None)
        {
            PLOGD << "InternetOpenUrlA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Url:" << sc(lpszUrl)
                << "  ,Headers" << sc(lpszHeaders)
                << "  ,Status:Success" << endl;
            WinNetBuffer << "InternetOpenUrlA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Url:" << sc(lpszUrl)
                << "  ,Headers" << sc(lpszHeaders)
                << "  ,Status:Success" << L"\n";
            UdpSend();
        }
    }
    else if (Lv > None)
    {
        PLOGD << "InternetOpenUrlA->Agent:" << InternetOpenHandleMap[hInternet]
            << "  ,Url:" << sc(lpszUrl)
            << "  ,Headers" << sc(lpszHeaders)
            << "  ,Status:Failed" << endl;
        WinNetBuffer << "InternetOpenUrlA->Agent:" << InternetOpenHandleMap[hInternet]
            << "  ,Url:" << sc(lpszUrl)
            << "  ,Headers" << sc(lpszHeaders)
            << "  ,Status:Failed" << "\n";
        UdpSend();
    }
        
    return rtn;
}

HINTERNET WINAPI MyWinNetApi::MyInternetOpenUrlW(
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
        if (Lv > None)
        {
            PLOGD << "InternetOpenUrlA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Url:" << sc(lpszUrl)
                << "  ,Headers" << sc(lpszHeaders)
                << "  ,Status:Success" << endl;
            WinNetBuffer << "InternetOpenUrlA->Agent:" << InternetOpenHandleMap[hInternet]
                << "  ,Url:" << sc(lpszUrl)
                << "  ,Headers" << sc(lpszHeaders)
                << "  ,Status:Success" << L"\n";
            UdpSend();
        }
            
    }
    else if (Lv > None)
    {
        PLOGD << "InternetOpenUrlA->Agent:" << InternetOpenHandleMap[hInternet]
            << "  ,Url:" << sc(lpszUrl)
            << "  ,Headers" << sc(lpszHeaders)
            << "  ,Status:Failed" << endl;
        WinNetBuffer << "InternetOpenUrlA->Agent:" << InternetOpenHandleMap[hInternet]
            << "  ,Url:" << sc(lpszUrl)
            << "  ,Headers" << sc(lpszHeaders)
            << "  ,Status:Success" << L"\n";
        UdpSend();
    }
        
    return rtn;
}

HINTERNET WINAPI  MyWinNetApi::MyInternetConnectA(
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
            if (Lv > Critial)
            {
                PLOGD << "InternetConnectA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:FTP  ,Status:Success" << endl;
                WinNetBuffer << "InternetConnectA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:FTP  ,Status:Success" << L"\n";
                UdpSend();
            }
            break;
        case INTERNET_SERVICE_HTTP:
            HttpSessionMap[rtn] = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(lpszServerName);
            if (Lv > Critial)
            {
                PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:HTTP  ,Status:Success" << endl;
                WinNetBuffer << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:HTTP  ,Status:Success" << L"\n";
                UdpSend();
            }
        default:
            if (Lv > Critial)
            {
                PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:Unknows  ,Status:Success" << endl;
                WinNetBuffer << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:Unknows  ,Status:Success" << L"\n";
                UdpSend();
            }
        }
    }
    else
    {
        switch (dwService)
        {
        case INTERNET_SERVICE_FTP:
            if (Lv > Critial)
            {
                PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:FTP  ,Status:Failed" << endl;
                WinNetBuffer << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:FTP  ,Status:Failed" << L"\n";
                UdpSend();
            }
                
            break;
        case INTERNET_SERVICE_HTTP:
            if (Lv > Critial)
            {
                PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:HTTP  ,Status:Failed" << endl;
                WinNetBuffer << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:HTTP  ,Status:Failed" << L"\n";
                UdpSend();
            }
                
        default:
            if (Lv > Critial)
            {
                PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:Unknows  ,Status:Failed" << endl;
                WinNetBuffer << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:Unknows  ,Status:Failed" << L"\n";
                UdpSend();
            }
                
        }
    }
    return rtn;
}

HINTERNET WINAPI  MyWinNetApi::MyInternetConnectW(
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
            if (Lv > Critial)
            {
                PLOGD << "InternetOpenW->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:FTP  ,Status:Success" << endl;
                WinNetBuffer << "InternetOpenW->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:FTP  ,Status:Success" << L"\n";
                UdpSend();
            }
                
            break;
        case INTERNET_SERVICE_HTTP:
            HttpSessionMap[rtn] = lpszServerName;
            if (Lv > Critial)
            {
                PLOGD << "InternetOpenW->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:HTTP  ,Status:Success" << endl;
                WinNetBuffer << "InternetOpenW->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:HTTP  ,Status:Success" << L"\n";
                UdpSend();
            }
                
        default:
            if (Lv > Critial)
            {
                PLOGD << "InternetOpenW->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:Unknown  ,Status:Success" << endl;
                WinNetBuffer << "InternetOpenW->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:Unknown  ,Status:Success" << L"\n";
                UdpSend();
            }
                
        }
    }
    else
    {
        switch (dwService)
        {
        case INTERNET_SERVICE_FTP:
            if (Lv > Critial)
            {
                PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:FTP  ,Status:Failed" << endl;
                WinNetBuffer << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:FTP  ,Status:Failed" << endl;
                UdpSend();
            }
                
            break;
        case INTERNET_SERVICE_HTTP:
            if (Lv > Critial)
            {
                PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:HTTP  ,Status:Failed" << endl;
                WinNetBuffer << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:HTTP  ,Status:Failed" << endl;
                UdpSend();
            }
                
        default:
            if (Lv > Critial)
            {
                PLOGD << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:Unknows  ,Status:Failed" << endl;
                WinNetBuffer << "InternetOpenA->Agent:" << InternetOpenHandleMap[hInternet]
                    << "  ,Server:" << sc(lpszServerName)
                    << "  ,ServerPort:" << nServerPort
                    << "  ,UserName:" << sc(lpszUserName)
                    << "  ,Password:" << sc(lpszPassword)
                    << " ServiceType:Unknows  ,Status:Failed" << endl;
                UdpSend();
            }
                
        }
    }
    return rtn;
}

BOOL WINAPI MyWinNetApi::MyInternetReadFile(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
)
{
    BOOL rtn = InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    if (Lv > Critial)
    {
        PLOGD << "InternetReadFile->FileName:" << InternetFileHandleMap[hFile]
            << "  ,NumberOfBytesRead:" << *lpdwNumberOfBytesRead
            << "  ,Status:" << rtn << endl;
        WinNetBuffer << "InternetReadFile->FileName:" << InternetFileHandleMap[hFile]
            << "  ,NumberOfBytesRead:" << *lpdwNumberOfBytesRead
            << "  ,Status:" << rtn << endl;
        UdpSend();
    }
    return rtn;
}

BOOL WINAPI MyWinNetApi::MyInternetReadFileExA(
    HINTERNET           hFile,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
)
{
    BOOL rtn = InternetReadFileExA(hFile, lpBuffersOut, dwFlags, dwContext);
    if (Lv > Critial)
    {
        PLOGD << "InternetReadFileExA->FileName:" << InternetFileHandleMap[hFile]
            << "  ,Status:" << rtn << endl;
        WinNetBuffer << "InternetReadFileExA->FileName:" << InternetFileHandleMap[hFile]
            << "  ,Status:" << rtn << endl;
        UdpSend();
    }
        
    return rtn;
}

BOOL WINAPI MyWinNetApi::MyInternetReadFileExW(
    HINTERNET           hFile,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
)
{
    BOOL rtn = InternetReadFileExW(hFile, lpBuffersOut, dwFlags, dwContext);
    if (Lv > Critial)
    {
        PLOGD << "InternetReadFileExW->FileName:" << InternetFileHandleMap[hFile]
            << "  ,Status:" << rtn << endl;
        WinNetBuffer << "InternetReadFileExW->FileName:" << InternetFileHandleMap[hFile]
            << "  ,Status:" << rtn << endl;
        UdpSend();
    }

    return rtn;
}

BOOL WINAPI MyWinNetApi::MyInternetWriteFile(
    HINTERNET hFile,
    LPCVOID   lpBuffer,
    DWORD     dwNumberOfBytesToWrite,
    LPDWORD   lpdwNumberOfBytesWritten
)
{
    BOOL rtn = InternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
    if (Lv > None)
    {
        PLOGD << "InternetWriteFile->FileName:" << InternetFileHandleMap[hFile]
            << "  ,NumberOfBytesWritten:" << *lpdwNumberOfBytesWritten
            << "  ,Status:" << rtn << endl;
        WinNetBuffer << "InternetWriteFile->FileName:" << InternetFileHandleMap[hFile]
            << "  ,NumberOfBytesWritten:" << *lpdwNumberOfBytesWritten
            << "  ,Status:" << rtn << endl;
        UdpSend();
    }
        
    return rtn;
}

HINTERNET WINAPI MyWinNetApi::MyHttpOpenRequestA(
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
        if (Lv > Critial)
        {
            PLOGD << "HttpOpenRequestA->Server:" << HttpSessionMap[hConnect]
                << "  ,Method:" << ((lpszVerb == NULL) ? "Get" : sc(lpszVerb))
                << "  ,Target:" << sc(lpszObjectName)
                << "  ,Referrer:" << sc(lpszReferrer) << endl;
            WinNetBuffer << "HttpOpenRequestA->Server:" << HttpSessionMap[hConnect]
                << "  ,Method:" << ((lpszVerb == NULL) ? "Get" : sc(lpszVerb))
                << "  ,Target:" << sc(lpszObjectName)
                << "  ,Referrer:" << sc(lpszReferrer) << endl;
            UdpSend();
        }
            
    }
    return rtn;
}

HINTERNET WINAPI MyWinNetApi::MyHttpOpenRequestW(
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
        if (Lv > Critial)
        {
            PLOGD << "HttpOpenRequestW->Server:" << HttpSessionMap[hConnect]
                << "  ,Method:" << (lpszVerb == NULL ? L"Get" : sc(lpszVerb))
                << "  ,Target:" << sc(lpszObjectName)
                << "  ,Referrer:" << sc(lpszReferrer) << endl;
            WinNetBuffer << "HttpOpenRequestW->Server:" << HttpSessionMap[hConnect]
                << "  ,Method:" << (lpszVerb == NULL ? L"Get" : sc(lpszVerb))
                << "  ,Target:" << sc(lpszObjectName)
                << "  ,Referrer:" << sc(lpszReferrer) << endl;
            UdpSend();
        }
            
    }
    return rtn;
}

BOOL WINAPI MyWinNetApi::MyHttpSendRequestA(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
)
{
    BOOL rtn = HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    if (Lv > None)
    {
        PLOGD << "HttpSendRequest->RequestTarget:" << InternetFileHandleMap[hRequest]
            << "  ,Headers:" << sc(lpszHeaders)
            << "  Status:" << rtn << endl;
        WinNetBuffer << "HttpSendRequest->RequestTarget:" << InternetFileHandleMap[hRequest]
            << "  ,Headers:" << sc(lpszHeaders)
            << "  Status:" << rtn << endl;
        UdpSend();
    }
        
    return rtn;
}

BOOL WINAPI MyWinNetApi::MyHttpSendRequestW(
    HINTERNET hRequest,
    LPCWSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
)
{
    BOOL rtn = HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    if (Lv > None)
    {
        PLOGD << "HttpSendRequest->RequestTarget:" << InternetFileHandleMap[hRequest]
            << "  ,Headers:" << sc(lpszHeaders)
            << "  Status:" << rtn << endl;
        WinNetBuffer << "HttpSendRequest->RequestTarget:" << InternetFileHandleMap[hRequest]
            << "  ,Headers:" << sc(lpszHeaders)
            << "  Status:" << rtn << endl;
        UdpSend();
    }
        
    return rtn;
}

BOOL WINAPI MyWinNetApi::MyHttpSendRequestExA(
    HINTERNET           hRequest,
    LPINTERNET_BUFFERSA lpBuffersIn,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
)
{
    BOOL rtn = HttpSendRequestExA(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);
    if (Lv > None)
    {
        PLOGD << "HttpSendRequest->RequestTarget:" << InternetFileHandleMap[hRequest]
            << "  Status:" << rtn << endl;
        WinNetBuffer << "HttpSendRequest->RequestTarget:" << InternetFileHandleMap[hRequest]
            << "  Status:" << rtn << endl;
        UdpSend();
    }
        
    return rtn;
}

BOOL WINAPI MyWinNetApi::MyHttpSendRequestExW(
    HINTERNET           hRequest,
    LPINTERNET_BUFFERSW lpBuffersIn,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
)
{
    BOOL rtn = HttpSendRequestExW(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);
    if (Lv > None)
    {
        PLOGD << "HttpSendRequest->RequestTarget:" << InternetFileHandleMap[hRequest]
            << "  Status:" << rtn << endl;
        WinNetBuffer << "HttpSendRequest->RequestTarget:" << InternetFileHandleMap[hRequest]
            << "  Status:" << rtn << endl;
        UdpSend();
    }
        
    return rtn;
}

void MyWinNetApi::UdpSend()
{
    if (UdpEnable)
    {
        const std::wstring& ws = WinNetBuffer.str();
        if (ws.size() == 0)
            return;
        else if (ws.size() < 30000 && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - WinNetTime).count() < 500)
            return;
        else if (WProcName.size() > 500 || ws.size() > 50000)
            PLOGE << "Data too long\n";
        else
        {
            memset(WinNetMessage, 0, sizeof(Message));
            WinNetMessage->type = 3;
            memcpy(WinNetMessage->Processname, WC.to_bytes(WProcName).c_str(), WProcName.size());
            memcpy(WinNetMessage->Data, WC.to_bytes(ws).c_str(), ws.size());
            if (sendto(WinNetSocket, (char*)WinNetMessage, sizeof(Message), 0, (SOCKADDR*)&WinNetServer, sizeof(SOCKADDR)) == SOCKET_ERROR)
                PLOGE << RtlGetLastErrorString() << std::endl;
            else
                WinNetBuffer.str(L"");
            WinNetTime = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
        }
    }
    else
        WinNetBuffer.str(L"");
    return;
}
void MyWinNetApi::InitWinNetApi()
{
    Check("InternetOpenA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetOpenA"), MyWinNetApi::MyInternetOpenA, NULL, &MyWinNetApi::InternetOpenAHook));
    Check("InternetOpenW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetOpenW"), MyWinNetApi::MyInternetOpenW, NULL, &MyWinNetApi::InternetOpenWHook));
    Check("InternetConnectA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetConnectA"), MyWinNetApi::MyInternetConnectA, NULL, &MyWinNetApi::InternetConnectAHook));
    Check("InternetConnectW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetConnectW"), MyWinNetApi::MyInternetConnectW, NULL, &MyWinNetApi::InternetConnectWHook));
    Check("InternetOpenUrlA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetOpenUrlA"), MyWinNetApi::MyInternetOpenUrlA, NULL, &MyWinNetApi::InternetOpenUrlAHook));
    Check("InternetOpenUrlW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetOpenUrlW"), MyWinNetApi::MyInternetOpenUrlW, NULL, &MyWinNetApi::InternetOpenUrlWHook));
    Check("InternetReadFile",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetReadFile"), MyWinNetApi::MyInternetReadFile, NULL, &MyWinNetApi::InternetReadFileHook));
    Check("InternetReadFileExA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetReadFileExA"), MyWinNetApi::MyInternetReadFileExA, NULL, &MyWinNetApi::InternetReadFileExAHook));
    Check("InternetReadFileExW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetReadFileExW"), MyWinNetApi::MyInternetReadFileExW, NULL, &MyWinNetApi::InternetReadFileExWHook));
    Check("InternetWriteFile",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "InternetWriteFile"), MyWinNetApi::MyInternetWriteFile, NULL, &MyWinNetApi::InternetWriteFileHook));
    Check("HttpOpenRequestA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "HttpOpenRequestA"), MyWinNetApi::MyHttpOpenRequestA, NULL, &MyWinNetApi::HttpOpenRequestAHook));
    Check("HttpOpenRequestW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "HttpOpenRequestW"), MyWinNetApi::MyHttpOpenRequestW, NULL, &MyWinNetApi::HttpOpenRequestWHook));
    Check("HttpSendRequestA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "HttpSendRequestA"), MyWinNetApi::MyHttpSendRequestA, NULL, &MyWinNetApi::HttpSendRequestAHook));
    Check("HttpSendRequestW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "HttpSendRequestW"), MyWinNetApi::MyHttpSendRequestW, NULL, &MyWinNetApi::HttpSendRequestWHook));
    Check("HttpSendRequestExA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "HttpSendRequestExA"), MyWinNetApi::MyHttpSendRequestExA, NULL, &MyWinNetApi::HttpSendRequestExAHook));
    Check("HttpSendRequestExW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("wininet")), "HttpSendRequestExW"), MyWinNetApi::MyHttpSendRequestExA, NULL, &MyWinNetApi::HttpSendRequestExWHook));

    ULONG ACLEntries[1] = { 0 };
    Check("InternetOpenA",LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::InternetOpenAHook));
    Check("InternetOpenW", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::InternetOpenWHook));
    Check("InternetConnectA", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::InternetConnectAHook));
    Check("InternetConnectW", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::InternetConnectWHook));
    Check("InternetOpenUrlA", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::InternetOpenUrlAHook));
    Check("InternetOpenUrlW", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::InternetOpenUrlWHook));
    Check("InternetReadFile", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::InternetReadFileHook));
    Check("InternetReadFileExA", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::InternetReadFileExAHook));
    Check("InternetReadFileExW", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::InternetReadFileExWHook));
    Check("InternetWriteFile", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::InternetWriteFileHook));
    Check("HttpOpenRequestA", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::HttpOpenRequestAHook));
    Check("HttpOpenRequestW", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::HttpOpenRequestWHook));
    Check("HttpSendRequestA", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::HttpSendRequestAHook));
    Check("HttpSendRequestW", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::HttpSendRequestWHook));
    Check("HttpSendRequestExA", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::HttpSendRequestExAHook));
    Check("HttpSendRequestExW", LhSetExclusiveACL(ACLEntries, 1, &MyWinNetApi::HttpSendRequestExWHook));

    if (SOCKET_ERROR == (WinNetSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)))
        PLOGE << "Init socket error" << endl;
    WinNetServer.sin_family = AF_INET;
    WinNetServer.sin_addr.s_addr = inet_addr(ServerAddr.c_str());
    WinNetServer.sin_port = htons(port);
    WinNetMessage = new Message;
    WinNetTime = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
}

