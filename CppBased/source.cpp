
#include <Windows.h>
#include <iostream>
#include <string>
#include<easyhook.h>
#include <comdef.h>
#include <stdio.h>

using std::wcout;
using std::endl;





int wmain(int argc, wchar_t** argv)
{
	WCHAR* dllToInject = const_cast<WCHAR*>(L".\\x64\\Debug\\hook.dll");
	WCHAR* dllToInject32 = const_cast<WCHAR*>(L".\\Debug\\hook.dll");
	//WCHAR* dllToInject32 = const_cast<WCHAR*>(L"C:\\Users\\hjc\\Desktop\\hook.dll");
	//std::wcout << argv[1];
	//std::wcout << dllToInject32;
	ULONG proc;
	//NTSTATUS nt = RhCreateAndInject(argv[1], const_cast<WCHAR*>(L""), CREATE_NEW_CONSOLE, EASYHOOK_INJECT_DEFAULT, dllToInject32, dllToInject, NULL, 0, &proc);
	//NTSTATUS nt = RhCreateAndInject(const_cast<WCHAR*>(L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"), const_cast<WCHAR*>(L""), CREATE_NEW_CONSOLE, EASYHOOK_INJECT_DEFAULT, dllToInject32, dllToInject, NULL, 0, &proc);
	NTSTATUS nt = RhCreateAndInject(const_cast<WCHAR*>(L"D:\\Program Files\\Typora\\Typora.exe"), const_cast<WCHAR*>(L""), CREATE_NEW_CONSOLE, EASYHOOK_INJECT_DEFAULT, dllToInject32, dllToInject, NULL, 0, &proc);
	if (nt != 0)
	{
		printf("RhInjectLibrary failed with error code = %d\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		std::wcout << err << "\n";
	}
	else
	{
		std::wcout << L"Library injected successfully.\n";
	}

	return 0;
}
