// dllmain.cpp : 定义 DLL 应用程序的入口点。

#include "pch.h"
#include"MyFileApi.h"
#include"MyProcessApi.h"
#include"MyWinNetApi.h"
#include"MyRegApi.h"
#include"MyServiceApi.h"
MyServiceApi ServiceApi;

DWORD gFreqOffset = 0;
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * inRemoteInfo);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	plog::init(plog::debug, "C:\\Users\\hjc98\\Desktop\\my.log");
	MyProcessApi* HC = (MyProcessApi*)(inRemoteInfo->UserData);
	PLOGD << "DL:"<<HC->out<<"  "<<HC<<endl;
	HC->InitProcessApi64();
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

	