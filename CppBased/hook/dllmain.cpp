// dllmain.cpp : 定义 DLL 应用程序的入口点。

#include "pch.h"
#include"MyFileApi.h"
#include"MyProcessApi.h"
#include"MyWinNetApi.h"
#include"MyRegApi.h"
#include"MyServiceApi.h"
 
DWORD gFreqOffset = 0;
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * inRemoteInfo);
void SocketInit();

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	std::string log_file = getenv("USERPROFILE");
	log_file += "\\Desktop\\my.log";
	plog::init(plog::debug, log_file.c_str());
	SocketInit();
	MyFileApi::SetLv(Debug);
	MyProcessApi::SetLv(Debug);
	MyWinNetApi::SetLv(Debug);
	MyRegApi::SetLv(Debug);
	//MyFileApi::InitFileApi32();
	MyProcessApi::InitProcessApi64();
	//MyRegApi::InitRegApi();
	//MyWinNetApi::InitWinNetApi();
	//InitFileApi64();
	//InitProcessApi64();
	//InitWinNetApi64();
	//InitRegApi();
	//ServiceApi.MyServiceApiInit();
	// If the threadId in the ACL is set to 0,
	// then internally EasyHook uses GetCurrentThreadId()

	// Disable the hook for the provided threadIds, enable for all others
	
	RhWakeUpProcess();
	return;
}

void SocketInit()
{
	if (::WSAStartup(socketVersion, &WSA) != 0)
		PLOGE << "Init socket dll error\n";
	else
		PLOGD << "WSA Init" << endl;
	if (SOCKET_ERROR == (GlobalSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)))
		PLOGE << "Init socket error"<<endl;
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servAddr.sin_port = htons((short)9999);
	int	nServAddlen = sizeof(servAddr);
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
		WSACleanup();
	}
	return true;
}