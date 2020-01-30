#coding:utf-8
from winappdbg.win32 import *
from winappdbg import *
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
    file_map = {}
    internet_map={}
    tmp = ''
    tmp_handle = 0
    
    #FileMultiThreadsTmp
    CreateFileA_Queue = Queue()
    CreateFileW_Queue = Queue()
    ReadFile_Queue = Queue()
    WriteFile_Queue = Queue()
    MoveFileA_Queue = Queue()
    MoveFileW_Queue = Queue()
    MoveFileExA_Queue = Queue()
    MoveFileExW_Queue = Queue()

    #ProcessMultiThreadsTmp
    CreateProcessA_Queue = Queue()
    CreateProcessW_Queue = Queue()
    CreateThread_Queue = Queue()
    OpenProcess_Queue = Queue()
    CreateRemoteThread_Queue = Queue()
    CreateRemoteThreadEx_Queue = Queue()

    #WininetMultiThreadsTmp
    InternetConnectA_Queue = Queue()
    InternetConnectW_Queue = Queue()


    apiHooks = apihooking

    def load_dll(self,event):
        logging.debug("Load:%s"%event.get_module().get_filename())
 
#FileApis
    #CreateFileA
    def pre_CreateFileA( self, event, ra, lpFileName, dwDesiredAccess,
             dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                                dwFlagsAndAttributes, hTemplateFile ):
        if FuncEnable['CreateFileA']:
            if len(self.tmp)>0:
                print "Tmp not Init! %s"%self.tmp
            file_name = event.get_process().peek_string(lpFileName)
            logging.debug("CreateFile->FileName:%s"%file_name)
            #self.__print_opening_unicode( event, "CreateFileW", lpFileName )
            self.CreateFileA_Queue.put(file_name, timeout=1)
            #self.tmp = file_name
    def post_CreateFileA(self,event,retval):
        if FuncEnable['CreateFileA']:
            try:
                #self.file_map[int(retval)] = {'file_name':self.tmp,'offset':0,'ReadBuffer':0,'ReadLength':0}
                if not self.CreateFileA_Queue.empty():
                    self.file_map[int(retval)] = {'file_name':self.CreateFileA_Queue.get(),'offset':0,'ReadBuffer':0,'ReadLength':0}
                    self.CreateFileA_Queue.task_done()
                else:
                    logging.debug("CreateFileA Error! No Handle!")
            except:
                print "Bind CreateFileError, tmp = %s, retval = %d"%(self.tmp,retval)
    
    #CreateFileW
    def pre_CreateFileW( self, event, ra, lpFileName, dwDesiredAccess,
             dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                                dwFlagsAndAttributes, hTemplateFile ):
        if FuncEnable['CreateFileW']:
            if len(self.tmp)>0:
                print "Tmp not Init! %s"%self.tmp
            file_name = event.get_process().peek_string(lpFileName, fUnicode = True )
            logging.debug("CreateFile->FileName:%s"%file_name)
            #self.__print_opening_unicode( event, "CreateFileW", lpFileName )
            self.CreateFileW_Queue.put(file_name)
    def post_CreateFileW(self,event,retval):
        if FuncEnable['CreateFileW']:
            try:
                if not self.CreateFileW_Queue.empty():
                    self.file_map[int(retval)] = {'file_name':self.CreateFileW_Queue.get(),'offset':0,'ReadBuffer':0,'ReadLength':0}
                    self.CreateFileW_Queue.task_done()
                else:
                    logging.debug("CreateFileW Error! No Handle!")
            except:
                print "Bind CreateFileError, tmp = %s, retval = %d"%(self.tmp,retval)
    
    #WriteFile
    def pre_WriteFile( self, event, ra, hFile, lpBuffer,
             nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
        if FuncEnable['WriteFile']:
            #print "WriteFile: Filename: %s, Handle:%08d, lpBuffer:%016x, nNumberOfBytesToWrite:%-d, offset:%d"%(self.file_map[hFile]['file_name'],hFile, lpBuffer, nNumberOfBytesToWrite,self.file_map[hFile]['offset'])
            try:
                #raw_input("WriteFile->Filename: %s"%self.file_map[hFile]['file_name'])
                jud = event.get_process().peek_string(lpBuffer,dwMaxSize=nNumberOfBytesToWrite).encode("ascii")
                #logging.debug("WriteFile->Filename: %s,WriteLength:%-d, Content:%s "%(self.file_map[hFile]['file_name'], nNumberOfBytesToWrite, event.get_process().peek_string(lpBuffer,dwMaxSize=nNumberOfBytesToWrite)))
                logging.debug("WriteFile->Filename: %s,WriteLength:%-d"%(self.file_map[hFile]['file_name'], nNumberOfBytesToWrite))
            except:
                '''
                try:
                    logging.debug("WriteFile->Filename: %s,WriteLength:%-d, Content:%s "%(self.file_map[hFile]['file_name'], nNumberOfBytesToWrite, event.get_process().peek_string(lpBuffer,fUnicode=True,dwMaxSize=nNumberOfBytesToWrite)))
                except:
                    try:
                        logging.debug("WriteFile->Filename: %s,WriteLength:%-d, Content:%s "%(self.file_map[hFile]['file_name'], nNumberOfBytesToWrite, self.__print__hex(event, lpBuffer,nNumberOfBytesToWrite)))
                    except:
                        logging.debug("WriteFile Error! Invilid Handle:%d"%hFile)
                '''
                try:
                    logging.debug("WriteFile->Filename: %s,WriteLength:%-d"%(self.file_map[hFile]['file_name'], nNumberOfBytesToWrite))
                except:
                    logging.debug("WriteFile Error! Invilid Handle:%s"%hFile)    
            #print event.get_process().peek_string(lpBuffer,dwMaxSize=nNumberOfBytesToWrite)
            #print "\n\n"
            try:
                self.file_map[hFile]['offset'] += nNumberOfBytesToWrite
            except:
                logging.debug("WriteFile Error! Invilid Handle:%s"%hFile) 
    def post_WriteFile(self,event,retval):
        pass
    
    #ReadFile
    def pre_ReadFile(self,event,ra,hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped):
        if FuncEnable['ReadFile']:
            #print "ReadFile: Filename: %s, Handle:%08d, lpBuffer:%016x, nNumberOfBytesToRead:%d, offset:%d"%(self.file_map[hFile]['file_name'],hFile, lpBuffer, nNumberOfBytesToRead,self.file_map[hFile]['offset'])
            #logging.debug("ReadFile: Filename: %s, Handle:%08d, lpBuffer:%016x, nNumberOfBytesToRead:%d, offset:%d"%(self.file_map[hFile]['file_name'],hFile, lpBuffer, nNumberOfBytesToRead,self.file_map[hFile]['offset']))
            try:
                self.file_map[hFile]['ReadBuffer'] = lpBuffer
                self.file_map[hFile]['ReadLength'] = lpNumberOfBytesRead
                self.file_map[hFile]['offset']+=nNumberOfBytesToRead
            except:
                logging.debug("Handle Error :%d"%hFile)
            self.ReadFile_Queue.put(hFile,timeout = 1)
    def post_ReadFile(self,event,retval):
        if FuncEnable['ReadFile']:
            try:
                if not self.ReadFile_Queue.empty():
                    tmp_handle = self.ReadFile_Queue.get()
                    self.ReadFile_Queue.task_done()
                    read_size = event.get_process().peek_int(self.file_map[tmp_handle]['ReadLength'])
                    #print "Filename:%s, Readsize:%d, Buffer:%d"%(self.file_map[self.tmp_handle]['file_name'],read_size,self.file_map[self.tmp_handle]['ReadBuffer'])
                    logging.debug("ReadFile->Filename:%s, Readsize:%d"%(self.file_map[tmp_handle]['file_name'],read_size))
                else:
                    logging.debug("ReadFile Error! No Handle!")
            except:
                logging.debug("ReadFile Error! Handle:%d"%tmp_handle)
    
    #MoveFileA
    def pre_MoveFileA(self, event, ra, lpExistingFileName, lpNewFileName):
        if FuncEnable['MoveFileA']:
            proc = event.get_process()
            self.MoveFileA_Queue.put([proc.peek_string(lpExistingFileName), proc.peek_string(lpNewFileName)])
    def post_MoveFileA(self,event, retval):
        if FuncEnable['MoveFileA']:
            try:
                if not self.MoveFileA_Queue.empty():
                        tmp = self.MoveFileA_Queue.get()
                        self.MoveFileA_Queue.task_done()
                        logging.debug("MoveFileA->From %s to %s, IsSucceed:%s"%(tmp[0], tmp[1], retval))
            except:
                logging.debug("MoveFileA Error!")
    
    #MoveFileW
    def pre_MoveFileW(self, event, ra, lpExistingFileName, lpNewFileName):
        if FuncEnable['MoveFileW']:
            proc = event.get_process()
            self.MoveFileW_Queue.put([proc.peek_string(lpExistingFileName,fUnicode=True), proc.peek_string(lpNewFileName,fUnicode=True)])
    def post_MoveFileW(self,event, retval):
        if FuncEnable['MoveFileW']:
            try:
                if not self.MoveFileW_Queue.empty():
                        tmp = self.MoveFileW_Queue.get()
                        self.MoveFileW_Queue.task_done()
                        logging.debug("MoveFileW->From %s to %s, IsSucceed:%s"%(tmp[0], tmp[1], retval))
            except:
                logging.debug("MoveFileW Error!")

    #MoveFileExA
    def pre_MoveFileExA(self, event, ra, lpExistingFileName, lpNewFileName, dwFlags):
        if FuncEnable['MoveFileExA']:
            proc = event.get_process()
            self.MoveFileExA_Queue.put([proc.peek_string(lpExistingFileName), proc.peek_string(lpNewFileName)])
    def post_MoveFileExA(self,event, retval):
        if FuncEnable['MoveFileExA']:
            try:
                if not self.MoveFileExA_Queue.empty():
                        tmp = self.MoveFileExA_Queue.get()
                        self.MoveFileExA_Queue.task_done()
                        logging.debug("MoveFile->From %s to %s, IsSucceed:%s"%(tmp[0], tmp[1], retval))
            except:
                logging.debug("MoveFileExA Error!")

    #MoveFileExW
    def pre_MoveFileExW(self, event, ra, lpExistingFileName, lpNewFileName, dwFlags):
        if FuncEnable['MoveFileExW']:
            proc = event.get_process()
            self.MoveFileExW_Queue.put([proc.peek_string(lpExistingFileName, fUnicode=True), proc.peek_string(lpNewFileName, fUnicode=True)])
    def post_MoveFileExW(self,event, retval):
        if FuncEnable['MoveFileExW']:
            try:
                if not self.MoveFileExW_Queue.empty():
                        tmp = self.MoveFileExW_Queue.get()
                        self.MoveFileExW_Queue.task_done()
                        logging.debug("MoveFile->From %s to %s, IsSucceed:%s"%(tmp[0], tmp[1], retval))
            except:
                logging.debug("MoveFileExW Error!")

#ProcessApis
    #CreateProcessA
    def pre_CreateProcessA(self, event, ra, lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
        if FuncEnable['CreateProcessA']:
            logging.debug("CreateProcess->Handle:%s, CommandLine:%s"%(event.get_process().peek_string(lpApplicationName), event.get_process().peek_string(lpCommandLine)))
    def post_CreateProcessA(self,event, retval):
        pass
    
    #CreateProcessW   
    def pre_CreateProcessW(self, event, ra, lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
        if FuncEnable['CreateProcessW']:
            logging.debug("CreateProcess->Handle:%s, CommandLine:%s"%(event.get_process().peek_string(lpApplicationName,fUnicode = True), event.get_process().peek_string(lpCommandLine, fUnicode = True)))
    def post_CreateProcessW(self, event, retval):
        pass
    
    #CreateThread
    def pre_CreateThread(self,event, ra, lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
        if FuncEnable['CreateThread']:
            self.CreateThread_Queue.put({'StartAddress':hex(int(event.get_process().peek_uint(lpStartAddress))), 'Parameter': lpParameter})
    def post_CreateThread(self,event, retval):
        if FuncEnable['CreateThread']:
            if not self.CreateThread_Queue.empty():
                da = self.CreateThread_Queue.get()
                self.CreateThread_Queue.task_done()
                da['Handle'] = retval
                try:
                    logging.debug('CreateThread->Handle:%s, StartAddress:%s, Parameter:%s'%(da['Handle'], da['StartAddress'], event.get_process().peek_string(da['Parameter'])))
                except:
                    try:
                        logging.debug('CreateThread->Handle:%s, StartAddress:%s, Parameter:%s'%(da['Handle'], da['StartAddress'], event.get_process().peek_string(da['Parameter'],fUnicode = True)))
                    except:
                        try:
                            logging.debug('CreateThread->Handle:%s, StartAddress:%s, Parameter:%s'%(da['Handle'], da['StartAddress'], self.__print__hex(event, da['Parameter'], 20)))
                        except:
                            logging.debug("CreateThread Parameter Error")
            else:
                logging.debug("CreateThread Failed!")
    
    #IsDebuggerPresent
    def pre_IsDebuggerPresent(self,event, ra):
        if FuncEnable['IsDebuggerPresent']:
            raw_input("Find Debugger")
    def post_IsDebuggerPresent(self, event, retval):
        if FuncEnable['IsDebuggerPresent']:
            print retval
            process = event.get_process()
            process.suspend()
            thread = event.get_thread()
            thread.set_register("Eax",0)
            raw_input(retval)
    
    #OpenProcess
    def pre_OpenProcess(self, event, ra, dwDesiredAccess, bInheritHandle, dwProcessId):
        if FuncEnable['OpenProcess']:
            try:
                self.OpenProcess_Queue.put([dwDesiredAccess, dwProcessId])
            except:
                logging.debug("OpenProcess Error!")
    def post_OpenProcess(self, event, retval):
        if FuncEnable['OpenProcess']:
            if not self.OpenProcess_Queue.empty():
                try:
                    tmp = self.OpenProcess_Queue.get()
                    self.OpenProcess_Queue.task_done()
                    logging.debug("OpenProcess->PID:%s  DesiredAccess:%s  ProcesHandle:%s"%(tmp[1], tmp[0], retval))
                except:
                    logging.debug("OpenProcess Error!")     
    
    #WriteProcessMemory
    def pre_WriteProcessMemory(self, event, ra, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten):
        if FuncEnable['WriteProcessMemory']:
            logging.debug("WriteProcessMemory->Handle:%s, BaseAddress:%s,  Content:%s"%(hProcess, hex(int(lpBaseAddress)), self.__print__hex(event, lpBuffer, nSize)))
    def post_WriteProcessMemory(self, event, retval):
        pass
    
    #WinExec
    def pre_WinExec(self, event, ra, lpCmdLine, uCmdShow):
        if FuncEnable['WinExec']:
            logging.debug("WinExec->CommandLine:%s, ShowOption:%s"%(lpCmdLine, uCmdShow))
    def post_WinExec(self, event, retval):
        pass

    #CreateRemoteThread
    def pre_CreateRemoteThread(self, event, ra, hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
        self.CreateRemoteThread_Queue.put([hex(self.uint(hProcess)),hex(self.uint(event.get_process().peek_int(lpStartAddress))),lpParameter])
    def post_CreateRemoteThread(self, event, retval):
        if FuncEnable['CreateRemoteThread']:
            if not self.CreateRemoteThread_Queue.empty():
                tmp = self.CreateRemoteThread_Queue.get()
                self.CreateRemoteThread_Queue.task_done()
                proc = event.get_process()
                try:
                    Parameter = proc.peek_string(tmp[2])
                except:
                    try:
                        Parameter = proc.peek_string(tmp[2], fUnicode=True)
                    except:
                        logging.debug("CreateRemoteThread Error!")
                        return retval
                finally:
                    logging.debug("CreateRemoteThread->Process:%s, StartAddress:%s, Parameter:%s, NewThreadHandle:%s"%(tmp[0], tmp[1], Parameter, retval))

    #CreateRemoteThreadEx
    def pre_CreateRemoteThreadEx(self, event, ra, hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId):
        self.CreateRemoteThreadEx_Queue.put([hex(self.uint(hProcess)),hex(self.uint(event.get_process().peek_int(lpStartAddress))),lpParameter])
    def post_CreateRemoteThreadEx(self, event, retval):
        if FuncEnable['CreateRemoteThreadEx']:
            if not self.CreateRemoteThreadEx_Queue.empty():
                tmp = self.CreateRemoteThreadEx_Queue.get()
                self.CreateRemoteThreadEx_Queue.task_done()
                proc = event.get_process()
                try:
                    Parameter = proc.peek_string(tmp[2])
                except:
                    try:
                        Parameter = proc.peek_string(tmp[2], fUnicode=True)
                    except:
                        logging.debug("CreateRemoteThread Error!")
                        return retval
                finally:
                    logging.debug("CreateRemoteThread->Process:%s, StartAddress:%s, Parameter:%s, NewThreadHandle:%s"%(tmp[0], tmp[1], Parameter, retval))

#WinRegApis
    #RegCreateKeyA
    def pre_RegCreateKeyA(self, event, ra, hKey, lpSubKey, phkResult):
        if FuncEnable['RegCreateKeyA']:
            try:
                logging.debug("RegCreateKey->KeyHandle:%s, CreateKey:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey)))
            except:
                logging.debug("RegCreateKeyError!")
    def post_RegCreateKeyA(self, event, retval):
        pass

    #RegCreateKeyW
    def pre_RegCreateKeyW(self, event, ra, hKey, lpSubKey, phkResult):
        if FuncEnable['RegCreateKeyW']:
            try:
                logging.debug("RegCreateKey->KeyHandle:%s, CreateKey:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True)))
            except:
                logging.debug("RegCreateKeyError!")
    def post_RegCreateKeyW(self, event, retval):
        pass

    #RegCreateKeyExA
    def pre_RegCreateKeyExA(self, event, ra, hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition):
        if FuncEnable['RegCreateKeyExA']:
            try:
                logging.debug("RegCreateKeyEx->KeyHandle:%s, CreateKey:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey)))
            except:
                logging.debug("RegCreateKeyError!")
    def post_RegCreateKeyExA(self, event, retval):
        pass
    
    #RegCreateKeyExW
    def pre_RegCreateKeyExW(self, event, ra, hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition):
        if FuncEnable['RegCreateKeyExW']:
            try:
                logging.debug("RegCreateKeyEx->KeyHandle:%s, CreateKey:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True)))
            except:
                logging.debug("RegCreateKeyError!")
    def post_RegCreateKeyExW(self, event, retval):
        pass

    #RegOpenKeyA
    def pre_RegOpenKeyA(self, event, ra, hKey, lpSubKey, phkResult):
        if FuncEnable['RegOpenKeyA']:
            try:
                logging.debug("RegOpenKey->KeyHandle:%s, OpenKey:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey)))
            except:
                logging.debug("RegOpenKeyError!")
    def post_RegOpenKeyA(self, event, retval):
        pass

    #RegOpenKeyExA
    def pre_RegOpenKeyExA(self, event, ra, hKey, lpSubKey, ulOptions, samDesired, phkResult):
        if FuncEnable['RegOpenKeyExA']:
            try:
                logging.debug("RegOpenKey->KeyHandle:%s, OpenKey:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey)))
            except:
                logging.debug("RegOpenKeyError!")
    def post_RegOpenKeyExA(self, event, retval):
        pass
    
    #RegOpenKeyW
    def pre_RegOpenKeyW(self, event, ra, hKey, lpSubKey, phkResult):
        if FuncEnable['RegOpenKeyW']:
            try:
                logging.debug("RegOpenKey->KeyHandle:%s, OpenKey:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True)))
            except:
                logging.debug("RegOpenKeyError!")
    def post_RegOpenKeyW(self, event, retval):
        pass

    #RegOpenKeyExW
    def pre_RegOpenKeyExW(self, event, ra, hKey, lpSubKey, ulOptions, samDesired,phkResult):
        if FuncEnable['RegOpenKeyExW']:
            try:
                logging.debug("RegOpenKey->KeyHandle:%s, OpenKey:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True)))
            except:
                logging.debug("RegOpenKeyError!")
    def post_RegOpenKeyExW(self, event, retval):
        pass


    #RegDeleteKeyA
    def pre_RegDeleteKeyA(self, event, ra, hKey, lpSubKey):
        if FuncEnable['RegDeleteKeyA']:
            try:
                logging.debug("RegDeleteKey->KeyHandle:%s, DeleteKey:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey)))
            except:
                logging.debug("RegDeleteKeyError!")
    def post_RegDeleteKeyA(self, event, retval):
        pass

    #RegDeleteKeyW
    def pre_RegDeleteKeyW(self, event, ra, hKey, lpSubKey):
        if FuncEnable['RegDeleteKeyW']:
            try:
                logging.debug("RegDeleteKey->KeyHandle:%s, DeleteKey:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True)))
            except:
                logging.debug("RegDeleteKeyError!")
    def post_RegDeleteKeyW(self, event, retval):
        pass


    #RegDeleteValueA
    def pre_RegDeleteValueA(self, event, ra, hKey, lpValueName):
        if FuncEnable['RegDeleteValueA']:
            try:
                logging.debug("RegDeleteValue->KeyHandle:%s, DeleteValue:%s"%(self.uint(hKey), event.get_process().peek_string(lpValueName)))
            except:
                logging.debug("RegDeleteValueError!")
    def post_RegDeleteValueA(self, event, retval):
        pass

    #RegDeleteValueW
    def pre_RegDeleteValueW(self, event, ra, hKey, lpValueName):
        if FuncEnable['RegDeleteValueW']:
            try:
                logging.debug("RegDeleteValue->KeyHandle:%s, DeleteValue:%s"%(self.uint(hKey), event.get_process().peek_string(lpValueName,fUnicode=True)))
            except:
                logging.debug("RegDeleteValueError!")
    def post_RegDeleteValueW(self, event, retval):
        pass

    #RegGetValueA
    def pre_RegGetValueA(self, event, ra, hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
        if FuncEnable['RegGetValueA']:
            try:
                logging.debug("RegGetValue->KeyHandle:%s, Key:%s, GetValueName:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey),event.get_process().peek_string(lpValue)))
            except:
                logging.debug("RegGetValueError!")
    def post_RegGetValueA(self, event, ra):
        pass

    #RegGetValueW
    def pre_RegGetValueW(self, event, ra, hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
        if FuncEnable['RegGetValueW']:
            try:
                logging.debug("RegGetValue->KeyHandle:%s, Key:%s, GetValueName:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True),event.get_process().peek_string(lpValue,fUnicode=True)))
            except:
                logging.debug("RegGetValueError!")
    def post_RegGetValueW(self, event, ra):
        pass

    #RegLoadKeyA
    def pre_RegLoadKeyA(self, event, ra, hKey, lpSubKey, lpFile):
        if FuncEnable['RegLoadKeyA']:
            try:
                logging.debug("RegLoadKey->KeyHandle:%s, Key:%s, LoadFile:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey),event.get_process().peek_string(lpFile)))
            except:
                logging.debug("RegLoadKeyError!")
    def post_RegLoadKeyA(self, event, retval):
        pass
    
    #RegLoadKeyW
    def pre_RegLoadKeyW(self, event, ra, hKey, lpSubKey, lpFile):
        if FuncEnable['RegLoadKeyW']:
            try:
                logging.debug("RegLoadKey->KeyHandle:%s, Key:%s, LoadFile:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True),event.get_process().peek_string(lpFile,fUnicode=True)))
            except:
                logging.debug("RegLoadKeyError!")
    def post_RegLoadKeyw(self, event, retval):
        pass
    
    #RegSetKeyValueA
    def pre_RegSetKeyValueA(self, event, ra, hKey, lpSubKey, lpValueName, dwType, lpData, cbData):
        if FuncEnable['RegSetKeyValueA']:
            try:
                logging.debug("RegSetKeyValue->KeyHandle:%s, Key:%s, UpdateValueName:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey),event.get_process().peek_string(lpValueName)))
            except:
                logging.debug("RegSetKeyValueError!")
    def post_RegSetKeyValueA(self, event, retval):
        pass

    #RegSetKeyValueW
    def pre_RegSetKeyValueW(self, event, ra, hKey, lpSubKey, lpValueName, dwType, lpData, cbData):
        if FuncEnable['RegSetKeyValueW']:
            try:
                logging.debug("RegSetKeyValue->KeyHandle:%s, Key:%s, UpdateValueName:%s"%(self.uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True),event.get_process().peek_string(lpValueName,fUnicode=True)))
            except:
                logging.debug("RegSetKeyValueError!")
    def post_RegSetKeyValueW(self, event, retval):
        pass

    #RegSetValueExA
    def pre_RegSetValueExA(self, event, ra, hKey, lpValueName, Reserved, dwType, lpData, cbData):
        if FuncEnable['RegSetValueExA']:
            try:
                logging.debug("RegSetValue->KeyHandle:%s, UpdateValueName:%s"%(self.uint(hKey) ,event.get_process().peek_string(lpValueName)))
            except:
                logging.debug("RegSetKeyValueError!")
    def post_RegSetValueExA(self, event, retval):
        pass

    #RegSetValueExW
    def pre_RegSetValueExW(self, event, ra, hKey, lpValueName, Reserved, dwType, lpData, cbData):
        if FuncEnable['RegSetValueExA']:
            try:
                logging.debug("RegSetValue->KeyHandle:%s, UpdateValueName:%s"%(self.uint(hKey) ,event.get_process().peek_string(lpValueName, fUnicode=True)))
            except:
                logging.debug("RegSetKeyValueError!")
    def post_RegSetValueExW(self, event, retval):
        pass

#WininetApis
    #InternetOpenA
    def pre_InternetOpenA(self, event, ra, lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags):
        if FuncEnable['InternetOpenA']:
            try:
                proc = event.get_process()
                logging.debug("InternetOpen->CallingEntry:%s, Proxy:%s, ProxyBpass:%s"%(proc.peek_string(lpszAgent), proc.peek_string(lpszProxy), proc.peek_string(lpszProxyBypass)))
            except:
                logging.debug("InternetOpenA Error!")
    def post_InternetOpenA(self, event, retval):
        pass

    #InternetOpenW
    def pre_InternetOpenW(self, event, ra, lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags):
        if FuncEnable['InternetOpenW']:
            try:
                proc = event.get_process()
                logging.debug("InternetOpen->CallingEntry:%s, Proxy:%s, ProxyBpass:%s"%(proc.peek_string(lpszAgent,fUnicode=True), proc.peek_string(lpszProxy,fUnicode=True), proc.peek_string(lpszProxyBypass,fUnicode=True)))
            except:
                logging.debug("InternetOpenW Error!")
    def post_InternetOpenW(self, event, retval):
        pass

    #InternetOpenUrlA
    def pre_InternetOpenUrlA(self, event, ra, hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext):
        if FuncEnable['InternetOpenUrlA']:
            try:
                proc = event.process()
                logging.debug("InternetOpenUrl->Url:%s, Headers:%s"%(proc.peek_string(lpszUrl), proc.peek_string(lpszHeaders)))
            except:
                logging.debug("InternetOpenUrl Error!")
    def post_InternetOpenUrlA(self, event, retval):
        pass

    #InternetOpenUrlW
    def pre_InternetOpenUrlW(self, event, ra, hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext):
        if FuncEnable['InternetOpenUrlW']:
            try:
                proc = event.process()
                logging.debug("InternetOpenUrl->Url:%s, Headers:%s"%(proc.peek_string(lpszUrl,fUnicode=True), proc.peek_string(lpszHeaders,fUnicode=True)))
            except:
                logging.debug("InternetOpenUrl Error!")
    def post_InternetOpenUrlW(self, event, retval):
        pass
    
    #InternetConnectA
    def pre_InternetConnectA(self, event, ra, hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext):
        if FuncEnable['InternetConnectA']:
            try:
                proc = event.get_process()
                logging.debug("InternetConnect->ServerName:%s, UserName:%s, Password:%s"%(proc.peek_string(lpszServerName), proc.peek_string(lpszUserName), proc.peek_string(lpszPassword)))
                self.InternetConnectA_Queue.put(proc.peek_string(lpszServerName))
            except:
                logging.debug("InternetConnectError!")
    def post_InternetConnectA(self, event, retval):
        if FuncEnable['InternetConnectA']:
            try:
                if not self.InternetConnectA_Queue.empty():
                    server = self.InternetConnectA_Queue.get()
                    self.InternetConnectA_Queue.task_done()
                    self.internet_map[int(retval)] = server
            except:
                logging.debug("InternetConnectError!")

    #InternetConnectW
    def pre_InternetConnectW(self, event, ra, hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext):
        if FuncEnable['InternetConnectW']:
            try:
                proc = event.get_process()
                logging.debug("InternetConnect->ServerName:%s, UserName:%s, Password:%s"%(proc.peek_string(lpszServerName, fUnicode=True), proc.peek_string(lpszUserName, fUnicode=True), proc.peek_string(lpszPassword, fUnicode=True)))
                self.InternetConnectW_Queue.put(proc.peek_string(lpszServerName,fUnicode=True))
            except:
                logging.debug("InternetConnectError!")
    def post_InternetConnectW(self, event, retval):
        if FuncEnable['InternetConnectW']:
            try:
                if not self.InternetConnectW_Queue.empty():
                    server = self.InternetConnectW_Queue.get()
                    self.InternetConnectW_Queue.task_done()
                    self.internet_map[int(retval)] = server
            except:
                logging.debug("InternetConnectError!")

    #HttpOpenRequestA
    def pre_HttpOpenRequestA(self, event, ra, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext):
        if FuncEnable['HttpOpenRequestA']:
            try:
                proc = event.get_process()
                logging.debug("HttpOpenRequest->Object:%s, Method:%s, Version:%s, Referrer:%s"%(self.internet_map[int(hConnect)]+proc.peek_string(lpszObjectName), proc.peek_string(lpszVerb), proc.peek_string(lpszVersion), proc.peek_string(lpszReferrer)))
            except:
                logging.debug("HttpOpenRequest Error!")
    def post_HttpOpenRequestA(self, event, retval):
        pass

    #HttpOpenRequestW
    def pre_HttpOpenRequestW(self, event, ra, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext):
        if FuncEnable['HttpOpenRequestW']:
            try:
                proc = event.get_process()
                logging.debug("HttpOpenRequest->Object:%s, Method:%s, Version:%s, Referrer:%s"%(self.internet_map[int(hConnect)]+proc.peek_string(lpszObjectName,fUnicode=True), proc.peek_string(lpszVerb,fUnicode=True), proc.peek_string(lpszVersion,fUnicode=True), proc.peek_string(lpszReferrer,fUnicode=True)))
            except:
                logging.debug("HttpOpenRequest Error!")
    def post_HttpOpenRequestW(self, event, retval):
        pass

# Some helper private methods

    def __print_opening_ansi( self, event, tag, pointer ):
        string = event.get_process().peek_string( pointer )
        tid    = event.get_tid()
        print  "%d: Opening %s: %s" % (tid, tag, string)

    def __print_opening_unicode( self, event, tag, pointer ):
        string = event.get_process().peek_string( pointer, fUnicode = True )
        tid    = event.get_tid()
        print  "%d: Opening %s: %s" % (tid, tag, string)

    def __print__hex(self,event, pointer, len):
        offset = 0
        rtn = '\n'
        while offset < len:
            rtn += "%02x"%int(event.get_process().peek_char(pointer+offset))
            offset += 1
            if offset % 8 == 0:
                rtn += ' '
            if offset % 64 == 0:
                rtn += '\n'
        return rtn

    def __print_success( self, event, retval ):
        tid = event.get_tid()
        if retval:
            print "%d: Success: %x" % (tid, retval)
        else:
            print "%d: Failed!" % tid

    def uint(self, num):
        return int(num)&0xffffffff

