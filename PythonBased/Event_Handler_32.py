#coding:utf-8
from winappdbg.win32 import *
from winappdbg import *
from HookedApis.WininetApi import *
from HookedApis.WinRegApi import *
from HookedApis.ProcessApi import *
from HookedApis.FileApi import *
from Hooking import *
import sys
import logging
import ctypes
from Queue import Queue
LOG_FORMAT = "%(asctime)s - %(message)s"
logging.basicConfig(filename=r'my.log',filemode='w',level=logging.DEBUG, format=LOG_FORMAT)
'''
Notification name	What does it mean?	                                    When is it received?
create_process	    The debugger has attached to a new process.	            When attaching to a process, when starting a new process for debugging, or when the debugee starts a new process and the bFollow flag was set to True.
exit_process	    A debugee process has finished executing.	            When a process terminates by itself or when the Process.kill method is called.
create_thread	    A debugee process has started a new thread.	            When the process creates a new thread or when the Process.start_thread method is called.
exit_thread	        A thread in a debugee process has finished executing.	When a thread terminates by itself or when the Thread.kill method is called.
load_dll	        A module in a debugee process was loaded.	            When a process loads a DLL module by itself or when the Process.inject_dll method is called.
unload_dll	        A module in a debugee process was unloaded.	            When a process unloads a DLL module by itself.
exception	        An exception was raised by the debugee.	                When a hardware fault is triggered or when the process calls RaiseException().
output_string	    The debuggee has sent a debug string.	                When the process calls OutputDebugString().
access_violation	Access violation exception was raised by the debugee.   When the debuggee tries to access invalid memory.
ms_vc_exception	    A C++ exception was raised by the debugee.	            When the debuggee calls RaiseException() with a custom exception code. This is what the implementation of throw() of the Visual Studio runtime does.
breakpoint	        A breakpoint exception was raised by the debugee.	    When a hardware fault is triggered by the int3 opcode, when the process calls DebugBreak(), or when a code breakpoint set by your program is triggered.
single_step	        A single step exception was raised by the debugee.	    When a hardware fault is triggered by the trap flag or the icebp opcode, or when a hardware breakpoint set by your program is triggered.
guard_page       	A guard page exception was raised by the debugee.	    When a guard page is hit or when a page breakpoint set by your program is triggered.
'''
class MyEventHandler( EventHandler ):

    apiHooks = apihooking

    def load_dll(self,event):
        logging.debug("Load:%s"%event.get_module().get_filename())
 
#FileApis
    #CreateFileA
    def pre_CreateFileA(self, event, ra, lpFileName, dwDesiredAccess,
        dwShareMode, lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile):
        MyPreCreateFileA(event, ra, lpFileName, dwDesiredAccess,
        dwShareMode, lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile)
    def post_CreateFileA(self,event,retval):
        MyPostCreateFileA(event,retval)

    #CreateFileW
    def pre_CreateFileW(self, event, ra, lpFileName, dwDesiredAccess,
        dwShareMode, lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile):
        MyPreCreateFileW(event, ra, lpFileName, dwDesiredAccess,
        dwShareMode, lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile)
    def post_CreateFileW(self,event,retval):
        MyPostCreateFileW(event,retval)
    
    #WriteFile
    def pre_WriteFile(self, event, ra, hFile, lpBuffer,
        nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
        MyPreWriteFile(event, ra, hFile, lpBuffer,
        nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped)
    def post_WriteFile(self,event,retval):
        MyPostWriteFile(event,retval)
    
    #ReadFile
    def pre_ReadFile(self, event, ra, hFile, lpBuffer, nNumberOfBytesToRead, 
        lpNumberOfBytesRead, lpOverlapped):
        MyPreReadFile(event, ra, hFile, lpBuffer, nNumberOfBytesToRead, 
        lpNumberOfBytesRead, lpOverlapped)
    def post_ReadFile(self,event,retval):
        MyPostReadFile(event,retval)
    
    #MoveFileA
    def pre_MoveFileA(self, event, ra, lpExistingFileName, lpNewFileName):
        MyPreMoveFileA(event, ra, lpExistingFileName, lpNewFileName)
    def post_MoveFileA(self,event, retval):
        MyPostMoveFileA(event, retval)
    
    #MoveFileW
    def pre_MoveFileW(self, event, ra, lpExistingFileName, lpNewFileName):
        MyPreMoveFileW(event, ra, lpExistingFileName, lpNewFileName)
    def post_MoveFileW(self,event, retval):
        MyPostMoveFileW(event, retval)

    #MoveFileExA
    def pre_MoveFileExA(self, event, ra, lpExistingFileName, lpNewFileName, dwFlags):
        MyPreMoveFileExA(event, ra, lpExistingFileName, lpNewFileName, dwFlags)
    def post_MoveFileExA(self,event, retval):
        MyPostMoveFileExA(event, retval)

    #MoveFileExW
    def pre_MoveFileExW(self, event, ra, lpExistingFileName, lpNewFileName, dwFlags):
        MyPreMoveFileExW(event, ra, lpExistingFileName, lpNewFileName, dwFlags)
    def post_MoveFileExW(self,event, retval):
        MyPostMoveFileExW(event, retval)

#ProcessApis
    #CreateProcessA
    def pre_CreateProcessA(self, event, ra, lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
        MyPreCreateProcessA(event, ra, lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
    def post_CreateProcessA(self,event, retval):
        MyPostCreateProcessA(event, retval)
    
    #CreateProcessW   
    def pre_CreateProcessW(self, event, ra, lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
        MyPreCreateProcessW(event, ra, lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
    def post_CreateProcessW(self, event, retval):
        MyPostCreateProcessW(event, retval)
    
    #CreateThread
    def pre_CreateThread(self,event, ra, lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
        MyPreCreateThread(event, ra, lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)
    def post_CreateThread(self,event, retval):
        MyPostCreateThread(event, retval)
    
    #IsDebuggerPresent
    def pre_IsDebuggerPresent(self,event, ra):
        MyPreIsDebuggerPresent(event, ra)
    def post_IsDebuggerPresent(self, event, retval):
        MyPostIsDebuggerPresent(event, retval)
    
    #OpenProcess
    def pre_OpenProcess(self, event, ra, dwDesiredAccess, bInheritHandle, dwProcessId):
        MyPreOpenProcess(event, ra, dwDesiredAccess, bInheritHandle, dwProcessId)
    def post_OpenProcess(self, event, retval):
        MyPostOpenProcess(event, retval) 
    
    #WriteProcessMemory
    def pre_WriteProcessMemory(self, event, ra, hProcess, lpBaseAddress, lpBuffer, 
    nSize, lpNumberOfBytesWritten):
        MyPreWriteProcessMemory(event, ra, hProcess, lpBaseAddress, lpBuffer, 
        nSize, lpNumberOfBytesWritten)
    def post_WriteProcessMemory(self, event, retval):
        MyPostWriteProcessMemory(event, retval)
    
    #WinExec
    def pre_WinExec(self, event, ra, lpCmdLine, uCmdShow):
        MyPreWinExec(event, ra, lpCmdLine, uCmdShow)
    def post_WinExec(self, event, retval):
        MyPostWinExec(event, retval)

    #CreateRemoteThread
    def pre_CreateRemoteThread(self, event, ra, hProcess, lpThreadAttributes, dwStackSize, 
    lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
        MyPreCreateRemoteThread(event, ra, hProcess, lpThreadAttributes, dwStackSize, 
    lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)
    def post_CreateRemoteThread(self, event, retval):
        MyPostCreateRemoteThread(event, retval)

    #CreateRemoteThreadEx
    def pre_CreateRemoteThreadEx(self, event, ra, hProcess, lpThreadAttributes, dwStackSize, 
    lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId):
       MyPreCreateRemoteThreadEx(event, ra, hProcess, lpThreadAttributes, dwStackSize, 
    lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId)
    def post_CreateRemoteThreadEx(self, event, retval):
        MyPostCreateRemoteThreadEx(event, retval)

#WinRegApis
    #RegCreateKeyA
    def pre_RegCreateKeyA(self, event, ra, hKey, lpSubKey, phkResult):
        MyPreRegCreateKeyA(event, ra, hKey, lpSubKey, phkResult)
    def post_RegCreateKeyA(self, event, retval):
        MyPostRegCreateKeyA(event, retval)

    #RegCreateKeyW
    def pre_RegCreateKeyW(self, event, ra, hKey, lpSubKey, phkResult):
        MyPreRegCreateKeyW(event, ra, hKey, lpSubKey, phkResult)
    def post_RegCreateKeyW(self, event, retval):
        MyPostRegCreateKeyW(event, retval)

    #RegCreateKeyExA
    def pre_RegCreateKeyExA(self, event, ra, hKey, lpSubKey, Reserved, 
    lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition):
        MyPreRegCreateKeyExA(event, ra, hKey, lpSubKey, Reserved, lpClass,
        dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition)
    def post_RegCreateKeyExA(self, event, retval):
        MyPostRegCreateKeyExA(event, retval)
    
    #RegCreateKeyExW
    def pre_RegCreateKeyExW(self, event, ra, hKey, lpSubKey, Reserved, lpClass, 
    dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition):
        MyPreRegCreateKeyExW(event, ra, hKey, lpSubKey, Reserved, lpClass,
        dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition)
    def post_RegCreateKeyExW(self, event, retval):
        MyPostRegCreateKeyExW(event, retval)

    #RegOpenKeyA
    def pre_RegOpenKeyA(self, event, ra, hKey, 
    lpSubKey, phkResult):
        MyPreRegOpenKeyA(event, ra, hKey, lpSubKey, phkResult)
    def post_RegOpenKeyA(self, event, retval):
        MyPostRegOpenKeyA(event, retval)

    #RegOpenKeyExA
    def pre_RegOpenKeyExA(self, event, ra, hKey, lpSubKey, ulOptions, samDesired, phkResult):
        MyPreRegOpenKeyExA(event, ra, hKey, lpSubKey, ulOptions, samDesired, phkResult)
    def post_RegOpenKeyExA(self, event, retval):
        MyPostRegOpenKeyExA(event, retval)
    
    #RegOpenKeyW
    def pre_RegOpenKeyW(self, event, ra, hKey, lpSubKey, phkResult):
        MyPreRegOpenKeyW(event, ra, hKey, lpSubKey, phkResult)
    def post_RegOpenKeyW(self, event, retval):
        MyPostRegOpenKeyW(event, retval)

    #RegOpenKeyExW
    def pre_RegOpenKeyExW(self, event, ra, hKey, lpSubKey, ulOptions, samDesired,phkResult):
        MyPreRegOpenKeyExW(event, ra, hKey, lpSubKey, ulOptions, samDesired,phkResult)
    def post_RegOpenKeyExW(self, event, retval):
        MyPostRegOpenKeyExW(event, retval)

    #RegDeleteKeyA
    def pre_RegDeleteKeyA(self, event, ra, hKey, lpSubKey):
        MyPreRegDeleteKeyA(event, ra, hKey, lpSubKey)
    def post_RegDeleteKeyA(self, event, retval):
        MyPostRegDeleteKeyA(event, retval)

    #RegDeleteKeyW
    def pre_RegDeleteKeyW(self, event, ra, hKey, lpSubKey):
        MyPreRegDeleteKeyW(event, ra, hKey, lpSubKey)
    def post_RegDeleteKeyW(self, event, retval):
        MyPostRegDeleteKeyW(event, retval)

    #RegDeleteValueA
    def pre_RegDeleteValueA(self, event, ra, hKey, lpValueName):
        MyPreRegDeleteValueA(event, ra, hKey, lpValueName)
    def post_RegDeleteValueA(self, event, retval):
        MyPostRegDeleteValueA(event, retval)

    #RegDeleteValueW
    def pre_RegDeleteValueW(self, event, ra, hKey, lpValueName):
        MyPreRegDeleteValueW(event, ra, hKey, lpValueName)
    def post_RegDeleteValueW(self, event, retval):
        MyPostRegDeleteValueW(event, retval)

    #RegGetValueA
    def pre_RegGetValueA(self, event, ra, hKey, lpSubKey, lpValue, dwFlags, 
    pdwType, pvData, pcbData):
        MyPreRegGetValueA(event, ra, hKey, lpSubKey, lpValue, dwFlags, 
        pdwType, pvData, pcbData)
    def post_RegGetValueA(self, event, ra):
        MyPostRegGetValueA(event, ra)

    #RegGetValueW
    def pre_RegGetValueW(self, event, ra, hKey, lpSubKey, lpValue, dwFlags, 
    pdwType, pvData, pcbData):
        MyPreRegGetValueW(event, ra, hKey, lpSubKey, lpValue, dwFlags,
         pdwType, pvData, pcbData)
    def post_RegGetValueW(self, event, ra):
        MyPostRegGetValueW(event, ra)

    #RegLoadKeyA
    def pre_RegLoadKeyA(self, event, ra, hKey, lpSubKey, lpFile):
        MyPreRegLoadKeyA(event, ra, hKey, lpSubKey, lpFile)
    def post_RegLoadKeyA(self, event, retval):
        MyPostRegLoadKeyA(event, retval)
    
    #RegLoadKeyW
    def pre_RegLoadKeyW(self, event, ra, hKey, lpSubKey, lpFile):
        MyPreRegLoadKeyW(event, ra, hKey, lpSubKey, lpFile)
    def post_RegLoadKeyw(self, event, retval):
        MyPostRegLoadKeyw(event, retval)
    
    #RegSetKeyValueA
    def pre_RegSetKeyValueA(self, event, ra, hKey, lpSubKey, lpValueName, 
    dwType, lpData, cbData):
        MyPreRegSetKeyValueA(event, ra, hKey, lpSubKey, lpValueName, 
        dwType, lpData, cbData)
    def post_RegSetKeyValueA(self, event, retval):
        MyPostRegSetKeyValueA(event, retval)

    #RegSetKeyValueW
    def pre_RegSetKeyValueW(self, event, ra, hKey, lpSubKey, lpValueName, 
    dwType, lpData, cbData):
        MyPreRegSetKeyValueW(event, ra, hKey, lpSubKey, lpValueName,
        dwType, lpData, cbData)
    def post_RegSetKeyValueW(self, event, retval):
        MyPostRegSetKeyValueW(event, retval)

    #RegSetValueExA
    def pre_RegSetValueExA(self, event, ra, hKey, lpValueName, Reserved, 
    dwType, lpData, cbData):
        MyPreRegSetValueExA(event, ra, hKey, lpValueName, Reserved,
        dwType, lpData, cbData)
    def post_RegSetValueExA(self, event, retval):
        MyPostRegSetValueExA(event, retval)

    #RegSetValueExW
    def pre_RegSetValueExW(self, event, ra, hKey, lpValueName, Reserved, 
    dwType, lpData, cbData):
        MyPreRegSetValueExW(event, ra, hKey, lpValueName, Reserved,
        dwType, lpData, cbData)
    def post_RegSetValueExW(self, event, retval):
        MyPostRegSetValueExW(event, retval)

#WininetApis
    #InternetOpenA
    def pre_InternetOpenA(self, event, ra, lpszAgent, dwAccessType, lpszProxy, 
    lpszProxyBypass, dwFlags):
        MyPreInternetOpenA(event, ra, lpszAgent, dwAccessType, lpszProxy, 
        lpszProxyBypass, dwFlags)
    def post_InternetOpenA(self, event, retval):
        MyPostInternetOpenA(event, retval)

    #InternetOpenW
    def pre_InternetOpenW(self, event, ra, lpszAgent, dwAccessType, lpszProxy, 
    lpszProxyBypass, dwFlags):
        MyPreInternetOpenW(event, ra, lpszAgent, dwAccessType, lpszProxy, 
        lpszProxyBypass, dwFlags)
    def post_InternetOpenW(self, event, retval):
        MyPostInternetOpenW(event, retval)

    #InternetOpenUrlA
    def pre_InternetOpenUrlA(self, event, ra, hInternet, lpszUrl, lpszHeaders, 
    dwHeadersLength, dwFlags, dwContext):
        MyPreInternetOpenUrlA(event, ra, hInternet, lpszUrl, lpszHeaders, 
        dwHeadersLength, dwFlags, dwContext)
    def post_InternetOpenUrlA(self, event, retval):
        MyPostInternetOpenUrlA(event, retval)

    #InternetOpenUrlW
    def pre_InternetOpenUrlW(self, event, ra, hInternet, lpszUrl, lpszHeaders, 
    dwHeadersLength, dwFlags, dwContext):
        MyPreInternetOpenUrlW(event, ra, hInternet, lpszUrl, lpszHeaders, 
        dwHeadersLength, dwFlags, dwContext)
    def post_InternetOpenUrlW(self, event, retval):
        MyPostInternetOpenUrlW(event, retval)
    
    #InternetConnectA
    def pre_InternetConnectA(self, event, ra, hInternet, lpszServerName, nServerPort, 
    lpszUserName, lpszPassword, dwService, dwFlags, dwContext):
        MyPreInternetConnectA(event, ra, hInternet, lpszServerName, nServerPort, 
        lpszUserName, lpszPassword, dwService, dwFlags, dwContext)
    def post_InternetConnectA(self, event, retval):
        MyPostInternetConnectA(event, retval)

    #InternetConnectW
    def pre_InternetConnectW(self, event, ra, hInternet, lpszServerName, nServerPort, 
    lpszUserName, lpszPassword, dwService, dwFlags, dwContext):
        MyPreInternetConnectW(event, ra, hInternet, lpszServerName, nServerPort, 
        lpszUserName, lpszPassword, dwService, dwFlags, dwContext)
    def post_InternetConnectW(self, event, retval):
        MyPostInternetConnectW(event, retval)

    #HttpOpenRequestA
    def pre_HttpOpenRequestA(self, event, ra, hConnect, lpszVerb, lpszObjectName, 
    lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext):
        MyPreHttpOpenRequestA(event, ra, hConnect, lpszVerb, lpszObjectName, 
        lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext)
    def post_HttpOpenRequestA(self, event, retval):
        MyPostHttpOpenRequestA(event, retval)

    #HttpOpenRequestW
    def pre_HttpOpenRequestW(self, event, ra, hConnect, lpszVerb, lpszObjectName, 
    lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext):
        MyPreHttpOpenRequestW(event, ra, hConnect, lpszVerb, lpszObjectName, 
        lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext)
    def post_HttpOpenRequestW(self, event, retval):
        MyPostHttpOpenRequestW(event, retval)
    
    #HttpSendRequestA
    def pre_HttpSendRequestA(self, event, ra, hRequest, lpszHeaders, dwHeadersLength, 
    lpOptional, dwOptionalLength):
        MyPreHttpSendRequestA(event, ra, hRequest, lpszHeaders, dwHeadersLength, 
        lpOptional, dwOptionalLength)
    def post_HttpSendRequestA(self, event, retval):
        MyPostHttpSendRequestA(event, retval)

    #HttpSendRequestW
    def pre_HttpSendRequestW(self, event, ra, hRequest, lpszHeaders, dwHeadersLength, 
    lpOptional, dwOptionalLength):
        MyPreHttpSendRequestW(event, ra, hRequest, lpszHeaders, dwHeadersLength, 
        lpOptional, dwOptionalLength)
    def post_HttpSendRequestW(self, event, retval):
        MyPostHttpSendRequestW(event, retval)
    
    #FtpCommandA
    def pre_FtpCommandA(self, event, ra, hConnect, fExpectResponse, dwFlags, lpszCommand, 
    dwContext, phFtpCommand):
        MyPreFtpCommandA(event, ra, hConnect, fExpectResponse, dwFlags, lpszCommand, 
        dwContext, phFtpCommand)
    def post_FtpCommandA(self, event, retval):
        MyPostFtpCommandA(event, retval)
    
    #FtpCommandA
    def pre_FtpCommandW(self, event, ra, hConnect, fExpectResponse, dwFlags, lpszCommand, 
    dwContext, phFtpCommand):
        MyPreFtpCommandW(event, ra, hConnect, fExpectResponse, dwFlags, lpszCommand, 
        dwContext, phFtpCommand)
    def post_FtpCommandW(self, event, retval):
        MyPostFtpCommandW(event, retval)

    #FtpGetFileA
    def pre_FtpGetFileA(self, event, ra, hConnect, lpszRemoteFile, lpszNewFile, fFailIfExists, 
    dwFlagsAndAttributes, dwFlags, dwContext):
        MyPreFtpGetFileA(event, ra, hConnect, lpszRemoteFile, lpszNewFile, fFailIfExists, 
        dwFlagsAndAttributes, dwFlags, dwContext)
    def post_FtpGetFileA(self, event, retval):
        MyPostFtpGetFileA(event, retval)

    #FtpGetFileW
    def pre_FtpGetFileW(self, event, ra, hConnect, lpszRemoteFile, lpszNewFile, fFailIfExists, 
    dwFlagsAndAttributes, dwFlags, dwContext):
        MyPreFtpGetFileW(event, ra, hConnect, lpszRemoteFile, lpszNewFile, fFailIfExists, 
        dwFlagsAndAttributes, dwFlags, dwContext)
    def post_FtpGetFileW(self, event, retval):
        MyPostFtpGetFileW(event, retval)

    #FtpOpenFileA
    def pre_FtpOpenFileA(self, event, ra, hConnect, lpszFileName, dwAccess, dwFlags, dwContext):
        MyPreFtpOpenFileA(event, ra, hConnect, lpszFileName, dwAccess, dwFlags, dwContext)
    def post_FtpOpenFileA(self, event, retval):
        MyPostFtpOpenFileA(event, retval)

    #FtpOpenFileW
    def pre_FtpOpenFileW(self, event, ra, hConnect, lpszFileName, dwAccess, dwFlags, dwContext):
        MyPreFtpOpenFileW(event, ra, hConnect, lpszFileName, dwAccess, dwFlags, dwContext)
    def post_FtpOpenFileW(self, event, retval):
        MyPostFtpOpenFileW(event, retval)
    
