// dllmain.cpp : 定义 DLL 应用程序的入口点。

#include "pch.h"
#include"MyFileApi.h"
#include"MyProcessApi.h"
#include"MyWinNetApi.h"
#include"MyRegApi.h"
#include"MyServiceApi.h"
 
DWORD gFreqOffset = 0;
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * inRemoteInfo);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	std::string log_file = getenv("USERPROFILE");
	log_file += "\\Desktop\\my.log";
	plog::init(plog::debug, log_file.c_str());
	if (::WSAStartup(socketVersion, &WSA) != 0)
		PLOGE << "Init socket dll error\n";
	else
		PLOGD << "WSA Init" << endl;

	MyFileApi::SetLv(Debug);
	MyProcessApi::SetLv(Debug);
	MyWinNetApi::SetLv(Debug);
	MyRegApi::SetLv(Debug);
	MyFileApi::InitFileApi64();
	MyProcessApi::InitProcessApi64();
	MyRegApi::InitRegApi();
	MyWinNetApi::InitWinNetApi();
	//Sleep(10000);
	//ServiceApi.MyServiceApiInit();
	// If the threadId in the ACL is set to 0,
	// then internally EasyHook uses GetCurrentThreadId()

	// Disable the hook for the provided threadIds, enable for all others
	WProcName = GetProcessNameByHandle(GetCurrentProcess());
	ProcName = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(GetProcessNameByHandle(GetCurrentProcess()));
	RhWakeUpProcess();
	return;
}


BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_DETACH:
		MyFileApi::UdpSend();
		MyProcessApi::UdpSend();
		MyRegApi::UdpSend();
		MyWinNetApi::UdpSend();
		//DeleteCriticalSection(&MyFileApi::CriticalLock);
		delete MyFileApi::FileMessage;
		delete MyProcessApi::ProcessMessage;
		delete MyRegApi::RegMessage;
		delete MyWinNetApi::WinNetMessage;
		WSACleanup();
	}
	return true;
}