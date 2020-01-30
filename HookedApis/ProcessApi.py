from winappdbg.win32 import *
from winappdbg import *
from Hooking import *
import sys
import logging
import ctypes
from Queue import Queue

class ProcessApi():
    file_map = {}
    internet_map={}
    tmp = ''
    tmp_handle = 0
    
    #ProcessMultiThreadsTmp
    CreateProcessA_Queue = Queue()
    CreateProcessW_Queue = Queue()
    CreateThread_Queue = Queue()
    OpenProcess_Queue = Queue()
    CreateRemoteThread_Queue = Queue()
    CreateRemoteThreadEx_Queue = Queue()

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

    def uint(self, num):
        return int(num)&0xffffffff