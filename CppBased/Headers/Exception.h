#pragma once
#include <Windows.h>
#include <iostream>
#include <string>

typedef struct APIHOOK
{
	BYTE oldcode[5];
	BYTE newcode[5];
	FARPROC OldProc;
	HANDLE ProcessHandle;
	bool status;
}APIHOOK, *LPAPIHOOK;
