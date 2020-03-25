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
	BOOL tmp;
	log_file += "\\Desktop\\my.log";
	plog::init(plog::debug, log_file.c_str());
	if (::WSAStartup(socketVersion, &WSA) != 0)
		PLOGE << "Init socket dll error\n";
	else
		PLOGD << "WSA Init" << endl;
	//Sleep(10000);
	Sleep(10000);
	if (inRemoteInfo->UserDataSize == 0)
	{
		MyFileApi::SetLv(Critial);
		MyProcessApi::SetLv(Critial);
		MyWinNetApi::SetLv(Critial);
		MyRegApi::SetLv(Critial);
		UdpEnable = false;
		PLOGE << "InData None!\n";
	}
	else
	{
		memcpy((void*)&Init, (void*)inRemoteInfo->UserData, inRemoteInfo->UserDataSize);
		PInf t = reinterpret_cast<PInf>(inRemoteInfo->UserData);
		NTSTATUS nt = RhIsX64Process(inRemoteInfo->HostPID, &tmp);
		dllpath_32 = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(t->dllpath_32);
		dllpath_64 = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(t->dllpath_64);
		if (nt)
		{
			PLOGE << "Defalut dected failed!\n";
			PLOGE << RtlGetLastErrorString()<<"\n";
			tmp = t->is_64;
		}
		if(t->FileApiEnabled)
			MyFileApi::SetLv(t->level);
		if(t->ProcessApiEnabled)
			MyProcessApi::SetLv(t->level);
		if(t->WinNetApiEnabled)
			MyWinNetApi::SetLv(t->level);
		if (t->RegApiEnabled)
			MyRegApi::SetLv(t->level);
		ServerAddr = t->ServerAddr;
		port = t->port;
		PLOGD << "Level:" << t->level;
		
		if (tmp)
		{
			MyFileApi::InitFileApi32();
			MyProcessApi::InitProcessApi32();
			MyRegApi::InitRegApi();
			MyWinNetApi::InitWinNetApi();
		}
		else
		{
			MyFileApi::InitFileApi64();
			MyProcessApi::InitProcessApi64();
			MyRegApi::InitRegApi();
			MyWinNetApi::InitWinNetApi();
		}
	}
	//MyServiceApi::MyServiceApiInit();
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