#pragma once
#include"Global.h"
#pragma warning(disable : 4996)
using std::endl;
using std::map;
using std::wstring;
using std::vector;



BOOL FileApiEnable = true;
std::wstring FilePrefix = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(getenv("USERPROFILE")) + L"\\Desktop\\Tmp\\";
vector<wstring> FileFilter = { L"my.log", L"MountPointManager" };

HOOK_TRACE_INFO WaitForSingleObjectExHook;
HOOK_TRACE_INFO CreateFileWHook;
HOOK_TRACE_INFO CreateFileAHook;
HOOK_TRACE_INFO ReadFileHook;
HOOK_TRACE_INFO ReadFileExHook;
HOOK_TRACE_INFO WriteFileHook;
HOOK_TRACE_INFO WriteFileExHook;
HOOK_TRACE_INFO DeleteFileAHook;
HOOK_TRACE_INFO DeleteFileWHook;
HOOK_TRACE_INFO MoveFileAHook;
HOOK_TRACE_INFO MoveFileWHook;
HOOK_TRACE_INFO MoveFileExAHook;
HOOK_TRACE_INFO MoveFileExWHook;
HOOK_TRACE_INFO CloseHandleHook;

DWORD WINAPI MyWaitForSingleObjectEx(
	HANDLE hHandle,
	DWORD  dwMilliseconds,
	BOOL   bAlertable
)
{
	PLOGD << "Wait->Time:" << dwMilliseconds
		<< ", AL:" << bAlertable << endl;
	return WaitForSingleObjectEx(hHandle, dwMilliseconds, FALSE);
}

inline bool FILTER_FILE_JUD(const wstring& in)
{
	for (auto x : FileFilter)
		if (in.find(x) != in.npos)
			return true;
	return false;
}

inline bool WRITE_FILE_JUD(const DWORD& in)
{
	return (in == GENERIC_ALL) || (in == GENERIC_WRITE) || (in == (GENERIC_READ | GENERIC_WRITE))
		|| (in == (GENERIC_EXECUTE | GENERIC_WRITE)) || (in == (GENERIC_EXECUTE | GENERIC_READ | GENERIC_WRITE));
}

BOOL WINAPI MyCloseHandle(
	HANDLE hObject
)
{
	if (WriteFileMap.find(hObject) != WriteFileMap.end())
	{
		PLOGD << "CloseHandle->FileName:" << *(WriteFileMap[hObject].lpFileName) << endl;
		CloseHandle(WriteFileMap[hObject].Shadow);
		WriteFileMap.erase(hObject);
	}
	return CloseHandle(hObject);
}

HANDLE WINAPI MyCreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	std::wstring c((TCHAR*)sc(lpFileName));
	HANDLE rtn = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	if (rtn && !FILTER_FILE_JUD(c))
	{
		FileMap[rtn] = c;
		if (WRITE_FILE_JUD(dwDesiredAccess))
		{
			std::wstring tmp = FilePrefix + c.substr(c.find_last_of('\\') + 1);
			HANDLE shadow = CreateFileW(tmp.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			if (shadow != INVALID_HANDLE_VALUE)
			{
				WriteFileMap[rtn] = { &FileMap[rtn], dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, shadow };
				PLOGD << "CreateFileW->FileName:" << c
					<< ",  Handle:" << rtn
					<< ", dwDesiredAccess:" << dwDesiredAccess
					<< ",  dwShareMode:" << dwShareMode
					<< ",  dwCreationDisposition:" << dwCreationDisposition
					<< ",  dwFlagsAndAttributes:" << dwFlagsAndAttributes << endl;
			}
		}
	}
	return rtn;
}

HANDLE WINAPI MyCreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	std::wstring c = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sc(lpFileName));
	HANDLE rtn = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	if (rtn && !FILTER_FILE_JUD(c))
	{
		FileMap[rtn] = c;
		if (WRITE_FILE_JUD(dwDesiredAccess))
		{
			std::wstring tmp = FilePrefix + c.substr(c.find_last_of('\\') + 1);
			HANDLE shadow = CreateFileW(tmp.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			if (shadow != INVALID_HANDLE_VALUE)
			{
				WriteFileMap[rtn] = { &FileMap[rtn], dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, shadow };
				PLOGD << "CreateFileW->FileName:" << c
					<< ",  Handle:" << rtn
					<< ", dwDesiredAccess:" << dwDesiredAccess
					<< ",  dwShareMode:" << dwShareMode
					<< ",  dwCreationDisposition:" << dwCreationDisposition
					<< ",  dwFlagsAndAttributes:" << dwFlagsAndAttributes << endl;
			}
		}
	}
	return rtn;
}

BOOL WINAPI MyReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
)
{
	std::wstring c;
	BOOL rtn =  ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	if (FileMap.find(hFile) == FileMap.end())
	{
		c = GetFileNameByFileHandle(hFile);
		FileMap[hFile] = c;
	}
	else
		c = FileMap[hFile];
	if (c.find(L"my.log") == c.npos && c.find(L"MountPointManager") == c.npos)
		PLOGD << "ReadFile->FileName:" << c
			<< ", NumberOfBytesRead:" << *lpNumberOfBytesRead
			<< ", Status:" << rtn << std::endl;
	return rtn;
}

BOOL WINAPI MyReadFileEx(
	HANDLE                          hFile,
	LPVOID                          lpBuffer,
	DWORD                           nNumberOfBytesToRead,
	LPOVERLAPPED                    lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	std::wstring c;
	BOOL rtn = ReadFileEx(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine);
	if (FileMap.find(hFile) == FileMap.end())
	{
		c = GetFileNameByFileHandle(hFile);
		FileMap[hFile] = c;
	}
	else
		c = FileMap[hFile];
	if (c.find(L"my.log") == c.npos && c.find(L"MountPointManager") == c.npos)
		PLOGD << "ReadFileEx->FileName:" << c
		<< ", NumberOfBytesToRead:" << nNumberOfBytesToRead
		<< ", Status:" << rtn << std::endl;
	return rtn;
}

BOOL WINAPI MyWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	std::wstring c;
	BOOL rtn = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	if (WriteFileMap.find(hFile) != WriteFileMap.end())
	{
		WT* tmp = &WriteFileMap[hFile];
		PLOGD << "WriteFile->FileName:" << *(tmp->lpFileName)
			<< "  ,Handle:" << hFile << endl;
		WriteFile(tmp->Shadow, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	}
	/*
	if (FileMap.find(hFile) == FileMap.end())
	{
		c = GetFileNameByFileHandle(hFile);
		FileMap[hFile] = c;
	}
	else
		c = FileMap[hFile];
	if (rtn && !FILTER_FILE_JUD(c))
	{
		if (WriteFileMap.find(hFile) != WriteFileMap.end())
		{
			WT* tmp = &WriteFileMap[hFile];
			DWORD written = 0;
			wstring TargetFile = FilePrefix + tmp->lpFileName->substr(tmp->lpFileName->find_last_of('\\') + 1);

			HANDLE track = CreateFileW(TargetFile.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (track == INVALID_HANDLE_VALUE)
				PLOGD << "TrackCreateFileError:" << TargetFile.c_str()<<"    "<<GetLastErrorAsString(GetLastError()) << endl;
			else
			{
				if (WriteFile(track, lpBuffer, nNumberOfBytesToWrite, &written, NULL) == FALSE)
					PLOGD << "TrackWriteFileError:" << GetLastErrorAsString(GetLastError()) << endl;
				else
					PLOGD << "TrackWriteFileSuccess:" << written << endl;
				CloseHandle(track);
			}
		}
	}
	*/
	return rtn;
}

BOOL WINAPI MyWriteFileEx(
	HANDLE                          hFile,
	LPCVOID                         lpBuffer,
	DWORD                           nNumberOfBytesToWrite,
	LPOVERLAPPED                    lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	std::wstring c;
	BOOL rtn = WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
	if (FileMap.find(hFile) == FileMap.end())
	{
		c = GetFileNameByFileHandle(hFile);
		FileMap[hFile] = c;
	}
	else
		c = FileMap[hFile];
	if (c.find(L"my.log") == c.npos && c.find(L"MountPointManager") == c.npos)
		PLOGD << "WriteFile->FileName:" << c
		<< ", NumberOfBytesWritten:" << nNumberOfBytesToWrite
		<< ", Status:" << rtn << std::endl;
	return rtn;
}

BOOL WINAPI MyDeleteFileA(
	LPCSTR lpFileName
)
{
	BOOL rtn =  DeleteFileA(lpFileName);
	PLOGD << "DeleteFileA->FileName:" << sc(lpFileName)
	<< ", Status:" << rtn << endl;
	return rtn;
}

BOOL WINAPI MyDeleteFileW(
	LPCWSTR lpFileName
)
{
	BOOL rtn = DeleteFileW(lpFileName);
	PLOGD << "DeleteFileW->FileName:" << sc(lpFileName)
	<<", Status:" << rtn<<endl;
	return rtn;
}

BOOL WINAPI MyMoveFileA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName
)
{
	bool rtn =  MoveFileA(lpExistingFileName, lpNewFileName);
	PLOGD << "MoveFileA->From:" << sc(lpExistingFileName)
	<< ", TO:" << lpNewFileName
	<< ", Status:" << rtn << endl;
	return rtn;
}

BOOL WINAPI MyMoveFileW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName
)
{
	bool rtn = MoveFileW(lpExistingFileName, lpNewFileName);
	PLOGD << "MoveFileA->From:" << sc(lpExistingFileName)
	<< ", TO:" << sc(lpNewFileName)
	<< ", Status:" << rtn << endl;
	return rtn;
}

BOOL WINAPI MyMoveFileExA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	DWORD  dwFlags
)
{
	bool rtn = MoveFileExA(lpExistingFileName, lpNewFileName, dwFlags);
	PLOGD << "MoveFileA->From:" << sc(lpExistingFileName)
	<< ", TO:" << sc(lpNewFileName)
	<< ", Status:" << rtn << endl;
	return rtn;
}

BOOL WINAPI MyMoveFileExW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	DWORD  dwFlags
)
{
	bool rtn = MoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
	PLOGD << "MoveFileA->From:" << sc(lpExistingFileName)
	<< ", TO:" << sc(lpNewFileName)
	<< ", Status:" << rtn << endl;
	return rtn;
}

inline void InitFileApi64()
{;
	Check("CreateFileW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateFileW"), MyCreateFileW, NULL, &CreateFileWHook));
	Check("CreateFileA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateFileA"), MyCreateFileA, NULL, &CreateFileAHook));
	//Check("ReadFile",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "ReadFile"), MyReadFile, NULL, &ReadFileHook));
	//Check("ReadFileEx",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "ReadFileEx"), MyReadFileEx, NULL, &ReadFileExHook));
	Check("WriteFile",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "WriteFile"), MyWriteFile, NULL, &WriteFileHook));
	//Check("WriteFileEx",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "WriteFileEx"), MyWriteFileEx, NULL, &WriteFileExHook));
	//Check("DeleteFileA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "DeleteFileA"), MyDeleteFileA, NULL, &DeleteFileAHook));
	//Check("DeleteFileW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "DeleteFileW"), MyDeleteFileW, NULL, &DeleteFileWHook));
	//Check("MoveFileA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "MoveFileA"), MyMoveFileA, NULL, &MoveFileAHook));
	//Check("MoveFileW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "MoveFileW"), MyMoveFileW, NULL, &MoveFileWHook));
	//Check("MoveFileExA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "MoveFileExA"), MyMoveFileExA, NULL, &MoveFileExAHook));
	//Check("MoveFileExW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "MoveFileExW"), MyMoveFileExW, NULL, &MoveFileExWHook));
	Check("CloseHandle", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CloseHandle"), MyCloseHandle, NULL, &CloseHandleHook));

	ULONG ACLEntries[1] = { 0 };
	Check("CreateFileW", LhSetExclusiveACL(ACLEntries, 1, &CreateFileWHook));
	Check("CreateFileA", LhSetExclusiveACL(ACLEntries, 1, &CreateFileAHook));
	//Check("ReadFile", LhSetExclusiveACL(ACLEntries, 1, &ReadFileHook));
	//Check("ReadFileEx", LhSetExclusiveACL(ACLEntries, 1, &ReadFileExHook));
	Check("WriteFile", LhSetExclusiveACL(ACLEntries, 1, &WriteFileHook));
	//Check("WriteFileEx", LhSetExclusiveACL(ACLEntries, 1, &WriteFileExHook));
	//Check("DeleteFileA", LhSetExclusiveACL(ACLEntries, 1, &DeleteFileAHook));
	//Check("DeleteFileW", LhSetExclusiveACL(ACLEntries, 1, &DeleteFileWHook));
	//Check("MoveFileA", LhSetExclusiveACL(ACLEntries, 1, &MoveFileAHook));
	//Check("MoveFileW", LhSetExclusiveACL(ACLEntries, 1, &MoveFileWHook));
	//Check("MoveFileExA", LhSetExclusiveACL(ACLEntries, 1, &MoveFileExAHook));
	//Check("MoveFileExW", LhSetExclusiveACL(ACLEntries, 1, &MoveFileExWHook));
	Check("CloseHandle", LhSetExclusiveACL(ACLEntries, 1, &CloseHandleHook));
}

inline void InitFileApi32()
{
	;
	Check("CreateFileW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateFileW"), MyCreateFileW, NULL, &CreateFileWHook));
	Check("CreateFileA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateFileA"), MyCreateFileA, NULL, &CreateFileAHook));
	//Check("ReadFile", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "ReadFile"), MyReadFile, NULL, &ReadFileHook));
	//Check("ReadFileEx", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "ReadFileEx"), MyReadFileEx, NULL, &ReadFileExHook));
	Check("WriteFile", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFile"), MyWriteFile, NULL, &WriteFileHook));
	//Check("WriteFileEx", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFileEx"), MyWriteFileEx, NULL, &WriteFileExHook));
	//Check("DeleteFileA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "DeleteFileA"), MyDeleteFileA, NULL, &DeleteFileAHook));
	//Check("DeleteFileW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "DeleteFileW"), MyDeleteFileW, NULL, &DeleteFileWHook));
	//Check("MoveFileA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFileA"), MyMoveFileA, NULL, &MoveFileAHook));
	//Check("MoveFileW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFileW"), MyMoveFileW, NULL, &MoveFileWHook));
	//Check("MoveFileExA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFileExA"), MyMoveFileExA, NULL, &MoveFileExAHook));
	//Check("MoveFileExW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFileExW"), MyMoveFileExW, NULL, &MoveFileExWHook));

	ULONG ACLEntries[1] = { 0 };
	Check("CreateFileW", LhSetExclusiveACL(ACLEntries, 1, &CreateFileWHook));
	Check("CreateFileA", LhSetExclusiveACL(ACLEntries, 1, &CreateFileAHook));
	//Check("ReadFile", LhSetExclusiveACL(ACLEntries, 1, &ReadFileHook));
	//Check("ReadFileEx", LhSetExclusiveACL(ACLEntries, 1, &ReadFileExHook));
	Check("WriteFile", LhSetExclusiveACL(ACLEntries, 1, &WriteFileHook));
	//Check("WriteFileEx", LhSetExclusiveACL(ACLEntries, 1, &WriteFileExHook));
	//Check("DeleteFileA", LhSetExclusiveACL(ACLEntries, 1, &DeleteFileAHook));
	//Check("DeleteFileW", LhSetExclusiveACL(ACLEntries, 1, &DeleteFileWHook));
	//Check("MoveFileA", LhSetExclusiveACL(ACLEntries, 1, &MoveFileAHook));
	//Check("MoveFileW", LhSetExclusiveACL(ACLEntries, 1, &MoveFileWHook));
	//Check("MoveFileExA", LhSetExclusiveACL(ACLEntries, 1, &MoveFileExAHook));
	//Check("MoveFileExW", LhSetExclusiveACL(ACLEntries, 1, &MoveFileExWHook));
}