#pragma once
#include <Windows.h>
#include <iostream>
#include <string>

void OnException(const EXCEPTION_DEBUG_INFO* pInfo) 
{
	std::wcout << pInfo->ExceptionRecord.ExceptionCode << std::endl;
	std::cin.get();
	std::wcout << TEXT("An exception was occured.") << std::endl;
}
