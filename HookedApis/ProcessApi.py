from winappdbg.win32 import *
from winappdbg import *
from Hooking import *
import sys
import logging
import ctypes
from Queue import Queue

tmp = ''

#ProcessMultiThreadsTmp
CreateProcessA_Queue = Queue()
CreateProcessW_Queue = Queue()
CreateThread_Queue = Queue()
OpenProcess_Queue = Queue()
CreateRemoteThread_Queue = Queue()
CreateRemoteThreadEx_Queue = Queue()

#ProcessApis
#CreateProcessA
def MyPreCreateProcessA(event, ra, lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
    lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
    if FuncEnable['CreateProcessA']:
        logging.debug("CreateProcess->Handle:%s, CommandLine:%s"%(event.get_process().peek_string(lpApplicationName), event.get_process().peek_string(lpCommandLine)))
def MyPostCreateProcessA(event, retval):
    pass

#CreateProcessW   
def MyPreCreateProcessW(event, ra, lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
    lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
    if FuncEnable['CreateProcessW']:
        logging.debug("CreateProcess->Handle:%s, CommandLine:%s"%(event.get_process().peek_string(lpApplicationName,fUnicode = True), event.get_process().peek_string(lpCommandLine, fUnicode = True)))
def MyPostCreateProcessW(event, retval):
    pass

#CreateThread
def MyPreCreateThread(event, ra, lpThreadAttributes, dwStackSize,
    lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
    if FuncEnable['CreateThread']:
        CreateThread_Queue.put({'StartAddress':hex(int(event.get_process().peek_uint(lpStartAddress))), 'Parameter': lpParameter})
def MyPostCreateThread(event, retval):
    if FuncEnable['CreateThread']:
        if not CreateThread_Queue.empty():
            da = CreateThread_Queue.get()
            CreateThread_Queue.task_done()
            da['Handle'] = retval
            try:
                logging.debug('CreateThread->Handle:%s, StartAddress:%s, Parameter:%s'%(da['Handle'], da['StartAddress'], event.get_process().peek_string(da['Parameter'])))
            except:
                try:
                    logging.debug('CreateThread->Handle:%s, StartAddress:%s, Parameter:%s'%(da['Handle'], da['StartAddress'], event.get_process().peek_string(da['Parameter'],fUnicode = True)))
                except:
                    try:
                        logging.debug('CreateThread->Handle:%s, StartAddress:%s, Parameter:%s'%(da['Handle'], da['StartAddress'], __print__hex(event, da['Parameter'], 20)))
                    except:
                        logging.debug("CreateThread Parameter Error")
        else:
            logging.debug("CreateThread Failed!")

#IsDebuggerPresent
def MyPreIsDebuggerPresent(event, ra):
    if FuncEnable['IsDebuggerPresent']:
        raw_input("Find Debugger")
def MyPostIsDebuggerPresent(event, retval):
    if FuncEnable['IsDebuggerPresent']:
        print retval
        process = event.get_process()
        process.suspend()
        thread = event.get_thread()
        thread.set_register("Eax",0)
        raw_input(retval)

#OpenProcess
def MyPreOpenProcess(event, ra, dwDesiredAccess, bInheritHandle, dwProcessId):
    if FuncEnable['OpenProcess']:
        try:
            OpenProcess_Queue.put([dwDesiredAccess, dwProcessId])
        except:
            logging.debug("OpenProcess Error!")
def MyPostOpenProcess(event, retval):
    if FuncEnable['OpenProcess']:
        if not OpenProcess_Queue.empty():
            try:
                tmp = OpenProcess_Queue.get()
                OpenProcess_Queue.task_done()
                logging.debug("OpenProcess->PID:%s  DesiredAccess:%s  ProcesHandle:%s"%(tmp[1], tmp[0], retval))
            except:
                logging.debug("OpenProcess Error!")     

#WriteProcessMemory
def MyPreWriteProcessMemory(event, ra, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten):
    if FuncEnable['WriteProcessMemory']:
        logging.debug("WriteProcessMemory->Handle:%s, BaseAddress:%s,  Content:%s"%(hProcess, hex(int(lpBaseAddress)), __print__hex(event, lpBuffer, nSize)))
def MyPostWriteProcessMemory(event, retval):
    pass

#WinExec
def MyPreWinExec(event, ra, lpCmdLine, uCmdShow):
    if FuncEnable['WinExec']:
        logging.debug("WinExec->CommandLine:%s, ShowOption:%s"%(lpCmdLine, uCmdShow))
def MyPostWinExec(event, retval):
    pass

#CreateRemoteThread
def MyPreCreateRemoteThread(event, ra, hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
    CreateRemoteThread_Queue.put([hex(uint(hProcess)),hex(uint(event.get_process().peek_int(lpStartAddress))),lpParameter])
def MyPostCreateRemoteThread(event, retval):
    if FuncEnable['CreateRemoteThread']:
        if not CreateRemoteThread_Queue.empty():
            tmp = CreateRemoteThread_Queue.get()
            CreateRemoteThread_Queue.task_done()
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
def MyPreCreateRemoteThreadEx(event, ra, hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId):
    CreateRemoteThreadEx_Queue.put([hex(uint(hProcess)),hex(uint(event.get_process().peek_int(lpStartAddress))),lpParameter])
def MyPostCreateRemoteThreadEx(event, retval):
    if FuncEnable['CreateRemoteThreadEx']:
        if not CreateRemoteThreadEx_Queue.empty():
            tmp = CreateRemoteThreadEx_Queue.get()
            CreateRemoteThreadEx_Queue.task_done()
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

def __print__hex(event, pointer, len):
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

def uint(num):
    return int(num)&0xffffffff