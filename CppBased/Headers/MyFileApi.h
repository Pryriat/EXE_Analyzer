#pragma once
#include"Global.h"
using std::endl;
using std::map;
using std::wstring;
using std::vector;
using std::to_wstring;

class MyFileApi
{
public:
	static CRITICAL_SECTION CriticalLock;
	static wstringstream Buffer;
	static std::wstring_convert<std::codecvt_utf8<wchar_t>> WC;
	static std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> FileTime;
	static Level Lv;
	static SOCKET FileSocket;
	static SOCKADDR_IN FileServer;
	static Message* FileMessage;
	static std::wstring FilePrefix;
	static vector<wstring> FileFilter;
	static std::map<HANDLE, std::wstring> FileMap;
	static std::map<HANDLE, WT> WriteFileMap;
	static HOOK_TRACE_INFO WaitForSingleObjectExHook;
	static HOOK_TRACE_INFO CreateFileWHook;
	static HOOK_TRACE_INFO CreateFileAHook;
	static HOOK_TRACE_INFO ReadFileHook;
	static HOOK_TRACE_INFO ReadFileExHook;
	static HOOK_TRACE_INFO WriteFileHook;
	static HOOK_TRACE_INFO WriteFileExHook;
	static HOOK_TRACE_INFO DeleteFileAHook;
	static HOOK_TRACE_INFO DeleteFileWHook;
	static HOOK_TRACE_INFO MoveFileAHook;
	static HOOK_TRACE_INFO MoveFileWHook;
	static HOOK_TRACE_INFO MoveFileExAHook;
	static HOOK_TRACE_INFO MoveFileExWHook;
	static HOOK_TRACE_INFO CloseHandleHook;
	static inline bool FILTER_FILE_JUD(const wstring& in);
	static inline bool WRITE_FILE_JUD(const DWORD& in);
	static void SetLv(Level Lv)
	{
		MyFileApi::Lv = Lv;
	}
	static BOOL WINAPI MyCloseHandle(
		HANDLE hObject
	);
	static HANDLE WINAPI MyCreateFileW(
		LPCWSTR               lpFileName,
		DWORD                 dwDesiredAccess,
		DWORD                 dwShareMode,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		DWORD                 dwCreationDisposition,
		DWORD                 dwFlagsAndAttributes,
		HANDLE                hTemplateFile
	);
	static HANDLE WINAPI MyCreateFileA(
		LPCSTR                lpFileName,
		DWORD                 dwDesiredAccess,
		DWORD                 dwShareMode,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		DWORD                 dwCreationDisposition,
		DWORD                 dwFlagsAndAttributes,
		HANDLE                hTemplateFile
	);
	static BOOL WINAPI MyReadFile(
		HANDLE       hFile,
		LPVOID       lpBuffer,
		DWORD        nNumberOfBytesToRead,
		LPDWORD      lpNumberOfBytesRead,
		LPOVERLAPPED lpOverlapped
	);
	static BOOL WINAPI MyReadFileEx(
		HANDLE                          hFile,
		LPVOID                          lpBuffer,
		DWORD                           nNumberOfBytesToRead,
		LPOVERLAPPED                    lpOverlapped,
		LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	);
	static BOOL WINAPI MyWriteFile(
		HANDLE       hFile,
		LPCVOID      lpBuffer,
		DWORD        nNumberOfBytesToWrite,
		LPDWORD      lpNumberOfBytesWritten,
		LPOVERLAPPED lpOverlapped
	);
	static BOOL WINAPI MyWriteFileEx(
		HANDLE                          hFile,
		LPCVOID                         lpBuffer,
		DWORD                           nNumberOfBytesToWrite,
		LPOVERLAPPED                    lpOverlapped,
		LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	);
	static BOOL WINAPI MyDeleteFileA(
		LPCSTR lpFileName
	);
	static BOOL WINAPI MyDeleteFileW(
		LPCWSTR lpFileName
	);
	static BOOL WINAPI MyMoveFileA(
		LPCSTR lpExistingFileName,
		LPCSTR lpNewFileName
	);
	static BOOL WINAPI MyMoveFileW(
		LPCWSTR lpExistingFileName,
		LPCWSTR lpNewFileName
	);
	static BOOL WINAPI MyMoveFileExA(
		LPCSTR lpExistingFileName,
		LPCSTR lpNewFileName,
		DWORD  dwFlags
	);
	static BOOL WINAPI MyMoveFileExW(
		LPCWSTR lpExistingFileName,
		LPCWSTR lpNewFileName,
		DWORD  dwFlags
	);
	static inline void InitFileApi64();
	static inline void InitFileApi32();
	static inline void UdpSend();
};
CRITICAL_SECTION MyFileApi::CriticalLock;
std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> MyFileApi::FileTime;
wstringstream MyFileApi::Buffer;
SOCKET MyFileApi::FileSocket;
PMS MyFileApi::FileMessage;
SOCKADDR_IN MyFileApi::FileServer;
std::wstring_convert<std::codecvt_utf8<wchar_t>> MyFileApi::WC;
std::wstring MyFileApi::FilePrefix = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(getenv("USERPROFILE")) + L"\\Desktop\\Tmp\\";
vector<wstring> MyFileApi::FileFilter = { L"my.log", L"MountPointManager" };
std::map<HANDLE, std::wstring> MyFileApi::FileMap;
std::map<HANDLE, WT> MyFileApi::WriteFileMap;
Level MyFileApi::Lv = Debug;
HOOK_TRACE_INFO MyFileApi::WaitForSingleObjectExHook;
HOOK_TRACE_INFO MyFileApi::CreateFileWHook;
HOOK_TRACE_INFO MyFileApi::CreateFileAHook;
HOOK_TRACE_INFO MyFileApi::ReadFileHook;
HOOK_TRACE_INFO MyFileApi::ReadFileExHook;
HOOK_TRACE_INFO MyFileApi::WriteFileHook;
HOOK_TRACE_INFO MyFileApi::WriteFileExHook;
HOOK_TRACE_INFO MyFileApi::DeleteFileAHook;
HOOK_TRACE_INFO MyFileApi::DeleteFileWHook;
HOOK_TRACE_INFO MyFileApi::MoveFileAHook;
HOOK_TRACE_INFO MyFileApi::MoveFileWHook;
HOOK_TRACE_INFO MyFileApi::MoveFileExAHook;
HOOK_TRACE_INFO MyFileApi::MoveFileExWHook;
HOOK_TRACE_INFO MyFileApi::CloseHandleHook;

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

inline bool MyFileApi::FILTER_FILE_JUD(const wstring& in)
{
	for (auto x : FileFilter)
		if (in.find(x) != in.npos)
			return true;
	return false;
}

inline bool MyFileApi::WRITE_FILE_JUD(const DWORD& in)
{
	return (in == GENERIC_ALL) || (in == GENERIC_WRITE) || (in == (GENERIC_READ | GENERIC_WRITE))
		|| (in == (GENERIC_EXECUTE | GENERIC_WRITE)) || (in == (GENERIC_EXECUTE | GENERIC_READ | GENERIC_WRITE));
}

BOOL WINAPI MyFileApi::MyCloseHandle(
	HANDLE hObject
)
{
	if (FileMap.find(hObject) != FileMap.end())
		FileMap.erase(hObject);
	/*
	if (WriteFileMap.find(hObject) != WriteFileMap.end())
	{
		if(Lv>Extra)
			PLOGD << "CloseHandle->FileName:" << *(WriteFileMap[hObject].lpFileName) << endl;
		CloseHandle(WriteFileMap[hObject].Shadow);
		WriteFileMap.erase(hObject);
	}
	*/
	return CloseHandle(hObject);
}

HANDLE WINAPI MyFileApi::MyCreateFileW(
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
		/*
		if (WRITE_FILE_JUD(dwDesiredAccess))
		{
			std::wstring tmp = FilePrefix + c.substr(c.find_last_of('\\') + 1);
			HANDLE shadow = CreateFileW(tmp.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			if (shadow != INVALID_HANDLE_VALUE)
			{
				if(Lv > Critial)
					WriteFileMap[rtn] = { &FileMap[rtn], dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, shadow };
				
			}
		}
		*/
		if (Lv > Extra)
		{
			PLOGD << "CreateFileW->FileName:" << c
				<< ",  Handle:" << rtn
				<< ", dwDesiredAccess:" << dwDesiredAccess
				<< ",  dwShareMode:" << dwShareMode
				<< ",  dwCreationDisposition:" << dwCreationDisposition
				<< ",  dwFlagsAndAttributes:" << dwFlagsAndAttributes << endl;
			//EnterCriticalSection(&CriticalLock);
			Buffer << L"CreateFileW->FileName:" << c
				<< L",  Handle:" << to_wstring(reinterpret_cast<ULONG>(rtn))
				<< L", dwDesiredAccess:" << to_wstring(dwDesiredAccess)
				<< L",  dwShareMode:" << to_wstring(dwShareMode)
				<< L",  dwCreationDisposition:" << to_wstring(dwCreationDisposition)
				<< L",  dwFlagsAndAttributes:" << to_wstring(dwFlagsAndAttributes) << L"\n";
			UdpSend();
			//LeaveCriticalSection(&CriticalLock);
		}
	}
	return rtn;
}

HANDLE WINAPI MyFileApi::MyCreateFileA(
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
		/*
		if (WRITE_FILE_JUD(dwDesiredAccess))
		{
			std::wstring tmp = FilePrefix + c.substr(c.find_last_of('\\') + 1);
			HANDLE shadow = CreateFileW(tmp.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			if (shadow != INVALID_HANDLE_VALUE)
			{
				if (Lv > Critial)
					WriteFileMap[rtn] = { &FileMap[rtn], dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, shadow };
			}
		}		_Gcount	8193	int

		*/
		
		if (Lv > Extra)
		{
			
			PLOGD << "CreateFileA->FileName:" << c
				<< ",  Handle:" << rtn
				<< ", dwDesiredAccess:" << dwDesiredAccess
				<< ",  dwShareMode:" << dwShareMode
				<< ",  dwCreationDisposition:" << dwCreationDisposition
				<< ",  dwFlagsAndAttributes:" << dwFlagsAndAttributes << endl;
			//EnterCriticalSection(&CriticalLock);
			Buffer << L"CreateFileW->FileName:" << c
				<< L",  Handle:" << to_wstring(reinterpret_cast<ULONG>(rtn))
				<< L", dwDesiredAccess:" << to_wstring(dwDesiredAccess)
				<< L",  dwShareMode:" << to_wstring(dwShareMode)
				<< L",  dwCreationDisposition:" << to_wstring(dwCreationDisposition)
				<< L",  dwFlagsAndAttributes:" << to_wstring(dwFlagsAndAttributes) << L"\n";
			UdpSend();
			//LeaveCriticalSection(&CriticalLock);
		}
	}
	return rtn;
}

BOOL WINAPI MyFileApi::MyReadFile(
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
	if (c.find(L"my.log") == c.npos && c.find(L"MountPointManager") == c.npos)\
	{
		if (Lv > Critial)
		{
			
			PLOGD << "ReadFile->FileName:" << c
				<< ", NumberOfBytesRead:" << *lpNumberOfBytesRead
				<< ", Status:" << rtn << std::endl;
			//EnterCriticalSection(&CriticalLock);
			Buffer << "ReadFile->FileName:" << c
				<< ", NumberOfBytesRead:" << *lpNumberOfBytesRead
				<< ", Status:" << rtn << L"\n";
			UdpSend();
			//LeaveCriticalSection(&CriticalLock);
		}
	}
		
			
	return rtn;
}

BOOL WINAPI MyFileApi::MyReadFileEx(
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
	{
		if (Lv > Critial)
		{
			
			PLOGD << "ReadFileEx->FileName:" << c
				<< ", NumberOfBytesToRead:" << nNumberOfBytesToRead
				<< ", Status:" << rtn << std::endl;
			//EnterCriticalSection(&CriticalLock);
			Buffer << "ReadFileEx->FileName:" << c
				<< ", NumberOfBytesToRead:" << nNumberOfBytesToRead
				<< ", Status:" << L"\n";
			UdpSend();
			//LeaveCriticalSection(&CriticalLock);
		}
	}
	return rtn;
}

BOOL WINAPI MyFileApi::MyWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	std::wstring c;
	BOOL rtn = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	/*
	if (WriteFileMap.find(hFile) != WriteFileMap.end())
	{
		WT* tmp = &WriteFileMap[hFile];
		if(Lv > None)
			PLOGD << "WriteFile->FileName:" << *(tmp->lpFileName)
				<< "  ,Handle:" << hFile << endl;
		//if(Lv > Critial )
			//WriteFile(tmp->Shadow, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	}
	*/
	if (FileMap.find(hFile) != FileMap.end())
	{
		if (Lv > None)
		{
			
			PLOGD << "WriteFile->FileName:" << FileMap[hFile]
				<< "  ,Handle:" << hFile << endl;
			//EnterCriticalSection(&CriticalLock);
			Buffer << "WriteFile->FileName:" << FileMap[hFile]
				<< "  ,Handle:" << hFile << L"\n";
			UdpSend();
			//LeaveCriticalSection(&CriticalLock);
		}
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

BOOL WINAPI MyFileApi::MyWriteFileEx(
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
	/*
	if (WriteFileMap.find(hFile) != WriteFileMap.end())
	{
		WT* tmp = &WriteFileMap[hFile];
		if(Lv > None)
			PLOGD << "WriteFileEx->FileName:" << *(tmp->lpFileName)
				<< "  ,Handle:" << hFile << endl;
		//if(Lv > Critial)
			//WriteFileEx(tmp->Shadow, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
	}
	*/
	if (FileMap.find(hFile) != FileMap.end())
	{
		if (Lv > None)
		{
			
			PLOGD << "WriteFile->FileName:" << FileMap[hFile]
				<< "  ,Handle:" << hFile << endl;
			//EnterCriticalSection(&CriticalLock);
			Buffer << "WriteFile->FileName:" << FileMap[hFile]
				<< "  ,Handle:" << hFile << endl;
			UdpSend();
			//LeaveCriticalSection(&CriticalLock);
		}
	}
	return rtn;
}

BOOL WINAPI MyFileApi::MyDeleteFileA(
	LPCSTR lpFileName
)
{
	BOOL rtn =  DeleteFileA(lpFileName);
	if (Lv > None)
	{
		
		PLOGD << "DeleteFileA->FileName:" << sc(lpFileName)
			<< ", Status:" << rtn << endl;
		//EnterCriticalSection(&CriticalLock);
		Buffer << "DeleteFileA->FileName:" << sc(lpFileName)
			<< ", Status:" << rtn << endl;
		UdpSend();
		//LeaveCriticalSection(&CriticalLock);
	}
	return rtn;
}

BOOL WINAPI MyFileApi::MyDeleteFileW(
	LPCWSTR lpFileName
)
{
	BOOL rtn = DeleteFileW(lpFileName);
	if (Lv > None)
	{
		
		PLOGD << "DeleteFileW->FileName:" << sc(lpFileName)
			<< ", Status:" << rtn << endl;
		//EnterCriticalSection(&CriticalLock);
		Buffer << "DeleteFileW->FileName:" << sc(lpFileName)
			<< ", Status:" << rtn << endl;
		UdpSend();
		//LeaveCriticalSection(&CriticalLock);
	}
	return rtn;
}

BOOL WINAPI MyFileApi::MyMoveFileA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName
)
{
	bool rtn =  MoveFileA(lpExistingFileName, lpNewFileName);
	if (Lv > None)
	{
		
		PLOGD << "MoveFileA->From:" << sc(lpExistingFileName)
			<< ", TO:" << lpNewFileName
			<< ", Status:" << rtn << endl;
		//EnterCriticalSection(&CriticalLock);
		Buffer << "MoveFileA->From:" << sc(lpExistingFileName)
			<< ", TO:" << lpNewFileName
			<< ", Status:" << rtn << endl;
		UdpSend();
		//LeaveCriticalSection(&CriticalLock);
	}
	return rtn;
}

BOOL WINAPI MyFileApi::MyMoveFileW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName
)
{
	bool rtn = MoveFileW(lpExistingFileName, lpNewFileName);
	if (Lv > None)
	{
		
		PLOGD << "MoveFileA->From:" << sc(lpExistingFileName)
			<< ", TO:" << sc(lpNewFileName)
			<< ", Status:" << rtn << endl;
		//EnterCriticalSection(&CriticalLock);
		Buffer << "MoveFileA->From:" << sc(lpExistingFileName)
			<< ", TO:" << sc(lpNewFileName)
			<< ", Status:" << rtn << endl;
		UdpSend();
		//LeaveCriticalSection(&CriticalLock);
	}
	return rtn;
}

BOOL WINAPI MyFileApi::MyMoveFileExA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	DWORD  dwFlags
)
{
	bool rtn = MoveFileExA(lpExistingFileName, lpNewFileName, dwFlags);
	if (Lv > None)
	{
		
		PLOGD << "MoveFileA->From:" << sc(lpExistingFileName)
			<< ", TO:" << sc(lpNewFileName)
			<< ", Status:" << rtn << endl;
		//EnterCriticalSection(&CriticalLock);
		Buffer << "MoveFileA->From:" << sc(lpExistingFileName)
			<< ", TO:" << sc(lpNewFileName)
			<< ", Status:" << rtn << endl;
		UdpSend();
		//LeaveCriticalSection(&CriticalLock);
	}
		
	return rtn;
}

BOOL WINAPI MyFileApi::MyMoveFileExW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	DWORD  dwFlags
)
{
	bool rtn = MoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
	if (Lv > None)
	{
		
		PLOGD << "MoveFileA->From:" << sc(lpExistingFileName)
			<< ", TO:" << sc(lpNewFileName)
			<< ", Status:" << rtn << endl;
		//EnterCriticalSection(&CriticalLock);
		Buffer << "MoveFileA->From:" << sc(lpExistingFileName)
			<< ", TO:" << sc(lpNewFileName)
			<< ", Status:" << rtn << endl;
		UdpSend();
		//LeaveCriticalSection(&CriticalLock);
	}
	return rtn;
}
inline void MyFileApi::UdpSend()
{
	const std::wstring& ws = Buffer.str();
	if (ws.size() == 0)
		return;
	else if (ws.size() < 38400 && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - FileTime).count() < 500)
		return;
	else if (WProcName.size() > 500 || ws.size() > 50000)
		PLOGE << "Data too long\n";
	else
	{
		memset(FileMessage, 0, sizeof(Message));
		FileMessage->type = 0;
		memcpy(FileMessage->Processname, WC.to_bytes(WProcName).c_str(), WProcName.size());
		memcpy(FileMessage->Data, WC.to_bytes(ws).c_str(), ws.size());
		if (sendto(FileSocket, (char*)FileMessage, sizeof(Message), 0, (SOCKADDR*)&FileServer, sizeof(SOCKADDR)) == SOCKET_ERROR)
			PLOGE << RtlGetLastErrorString() << std::endl;
		else
			Buffer.str(L"");
		FileTime = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
	}
	return;
}


inline void MyFileApi::InitFileApi64()
{
	PLOGD << "LV:" << Lv << endl;
	Check("CreateFileW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateFileW"), MyFileApi::MyCreateFileW, NULL, &MyFileApi::CreateFileWHook));
	Check("CreateFileA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CreateFileA"), MyFileApi::MyCreateFileA, NULL, &MyFileApi::CreateFileAHook));
	Check("ReadFile",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "ReadFile"), MyFileApi::MyReadFile, NULL, &MyFileApi::ReadFileHook));
	Check("ReadFileEx",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "ReadFileEx"), MyFileApi::MyReadFileEx, NULL, &MyFileApi::ReadFileExHook));
	Check("WriteFile",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "WriteFile"), MyFileApi::MyWriteFile, NULL, &MyFileApi::WriteFileHook));
	Check("WriteFileEx",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "WriteFileEx"), MyFileApi::MyWriteFileEx, NULL, &MyFileApi::WriteFileExHook));
	Check("DeleteFileA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "DeleteFileA"), MyFileApi::MyDeleteFileA, NULL, &MyFileApi::DeleteFileAHook));
	Check("DeleteFileW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "DeleteFileW"), MyFileApi::MyDeleteFileW, NULL, &MyFileApi::DeleteFileWHook));
	Check("MoveFileA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "MoveFileA"), MyFileApi::MyMoveFileA, NULL, &MyFileApi::MoveFileAHook));
	Check("MoveFileW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "MoveFileW"), MyFileApi::MyMoveFileW, NULL, &MyFileApi::MoveFileWHook));
	Check("MoveFileExA",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "MoveFileExA"), MyFileApi::MyMoveFileExA, NULL, &MyFileApi::MoveFileExAHook));
	Check("MoveFileExW",LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "MoveFileExW"), MyFileApi::MyMoveFileExW, NULL, &MyFileApi::MoveFileExWHook));
	Check("CloseHandle", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernelbase")), "CloseHandle"), MyFileApi::MyCloseHandle, NULL, &MyFileApi::CloseHandleHook));

	ULONG ACLEntries[1] = { 0 };
	Check("CreateFileW", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::CreateFileWHook));
	Check("CreateFileA", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::CreateFileAHook));
	Check("ReadFile", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::ReadFileHook));
	Check("ReadFileEx", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::ReadFileExHook));
	Check("WriteFile", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::WriteFileHook));
	Check("WriteFileEx", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::WriteFileExHook));
	Check("DeleteFileA", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::DeleteFileAHook));
	Check("DeleteFileW", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::DeleteFileWHook));
	Check("MoveFileA", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::MoveFileAHook));
	Check("MoveFileW", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::MoveFileWHook));
	Check("MoveFileExA", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::MoveFileExAHook));
	Check("MoveFileExW", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::MoveFileExWHook));
	Check("CloseHandle", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::CloseHandleHook));

	if (SOCKET_ERROR == (MyFileApi::FileSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)))
		PLOGE << "Init socket error" << endl;
	MyFileApi::FileServer.sin_family = AF_INET;
	MyFileApi::FileServer.sin_addr.s_addr = inet_addr("127.0.0.1");
	MyFileApi::FileServer.sin_port = htons((short)9999);
	MyFileApi::FileMessage = new Message;

	InitializeCriticalSection(&CriticalLock);
}

inline void MyFileApi::InitFileApi32()
{
	;
	Check("CreateFileW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateFileW"), MyFileApi::MyCreateFileW, NULL, &MyFileApi::CreateFileWHook));
	Check("CreateFileA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateFileA"), MyFileApi::MyCreateFileA, NULL, &MyFileApi::CreateFileAHook));
	Check("ReadFile", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "ReadFile"), MyFileApi::MyReadFile, NULL, &MyFileApi::ReadFileHook));
	Check("ReadFileEx", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "ReadFileEx"), MyFileApi::MyReadFileEx, NULL, &MyFileApi::ReadFileExHook));
	Check("WriteFile", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFile"), MyFileApi::MyWriteFile, NULL, &MyFileApi::WriteFileHook));
	Check("WriteFileEx", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFileEx"), MyFileApi::MyWriteFileEx, NULL, &MyFileApi::WriteFileExHook));
	Check("DeleteFileA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "DeleteFileA"), MyFileApi::MyDeleteFileA, NULL, &MyFileApi::DeleteFileAHook));
	Check("DeleteFileW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "DeleteFileW"), MyFileApi::MyDeleteFileW, NULL, &MyFileApi::DeleteFileWHook));
	Check("MoveFileA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFileA"), MyFileApi::MyMoveFileA, NULL, &MyFileApi::MoveFileAHook));
	Check("MoveFileW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFileW"), MyFileApi::MyMoveFileW, NULL, &MyFileApi::MoveFileWHook));
	Check("MoveFileExA", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFileExA"), MyFileApi::MyMoveFileExA, NULL, &MyFileApi::MoveFileExAHook));
	Check("MoveFileExW", LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFileExW"), MyFileApi::MyMoveFileExW, NULL, &MyFileApi::MoveFileExWHook));

	ULONG ACLEntries[1] = { 0 };
	Check("CreateFileW", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::CreateFileWHook));
	Check("CreateFileA", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::CreateFileAHook));
	Check("ReadFile", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::ReadFileHook));
	Check("ReadFileEx", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::ReadFileExHook));
	Check("WriteFile", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::WriteFileHook));
	Check("WriteFileEx", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::WriteFileExHook));
	Check("DeleteFileA", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::DeleteFileAHook));
	Check("DeleteFileW", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::DeleteFileWHook));
	Check("MoveFileA", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::MoveFileAHook));
	Check("MoveFileW", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::MoveFileWHook));
	Check("MoveFileExA", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::MoveFileExAHook));
	Check("MoveFileExW", LhSetExclusiveACL(ACLEntries, 1, &MyFileApi::MoveFileExWHook));
}