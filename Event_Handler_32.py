#coding:utf-8
from winappdbg.win32 import *
from winappdbg import *
import sys
import logging
import ctypes
from Queue import Queue
LOG_FORMAT = "%(asctime)s - %(message)s"
logging.basicConfig(filename=r'C:\Users\hjc\Desktop\my.log',filemode='w',level=logging.DEBUG, format=LOG_FORMAT)
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
    tmp = ''
    tmp_handle = 0
    
    #FileMultiThreadsTmp
    CreateFileA_Queue = Queue()
    CreateFileW_Queue = Queue()
    ReadFile_Queue = Queue()
    WriteFile_Queue = Queue()

    #ProcessMultiThreadsTmp
    CreateProcessA_Queue = Queue()
    CreateProcessW_Queue = Queue()
    CreateThread_Queue = Queue()

    apiHooks = {
        'kernel32.dll' : [
            #  Function            Parameters
            ( 'CreateFileA'     , (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE) ),
            ( 'CreateFileW'     , (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE) ),
            ( 'ReadFile'        , (HANDLE, PVOID, DWORD, PVOID, PVOID) ),
            ( 'ReadFileEx'      , (HANDLE, PVOID, DWORD, PVOID, PVOID) ),
            ( 'WriteFile'       , (HANDLE, PVOID, DWORD, PVOID, PVOID) ),
            ( 'WriteFileEx'     , (HANDLE, PVOID, DWORD, PVOID, PVOID) ),
            ( 'CreateProcessA'  , (PVOID, PVOID, PVOID, PVOID, BOOL, DWORD, PVOID, PVOID, PVOID, PVOID)),
            ( 'CreateProcessW'  , (PVOID, PVOID, PVOID, PVOID, BOOL, DWORD, PVOID, PVOID, PVOID, PVOID)),
            ( 'CreateThread'    , (PVOID, DWORD, PVOID, PVOID, DWORD, PVOID)),
            ( 'IsDebuggerPresent', ())
        ]
    }

    def load_dll(self,event):
        logging.debug("Load:%s"%event.get_module().get_filename())
 
#CreateFileA
    def pre_CreateFileA( self, event, ra, lpFileName, dwDesiredAccess,
             dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                                dwFlagsAndAttributes, hTemplateFile ):
        if len(self.tmp)>0:
            print "Tmp not Init! %s"%self.tmp
        file_name = event.get_process().peek_string(lpFileName)
        logging.debug("CreateFile:%s"%file_name)
        #self.__print_opening_unicode( event, "CreateFileW", lpFileName )
        self.CreateFileA_Queue.put(file_name, timeout=1)
        #self.tmp = file_name
    def post_CreateFileA(self,event,retval):
        try:
            #self.file_map[int(retval)] = {'file_name':self.tmp,'offset':0,'ReadBuffer':0,'ReadLength':0}
            if not self.CreateFileA_Queue.empty():
                self.file_map[int(retval)] = {'file_name':self.CreateFileA_Queue.get(),'offset':0,'ReadBuffer':0,'ReadLength':0}
                self.CreateFileA_Queue.task_done()
            else:
                logging.debug("CreateFileA Error! No Handle!")
        except:
            print "Bind CreateFileError, tmp = %s, retval = %d"%(tmp,retval)

#CreateFileW
    def pre_CreateFileW( self, event, ra, lpFileName, dwDesiredAccess,
             dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                                dwFlagsAndAttributes, hTemplateFile ):
        if len(self.tmp)>0:
            print "Tmp not Init! %s"%self.tmp
        file_name = event.get_process().peek_string(lpFileName, fUnicode = True )
        logging.debug("CreateFile:%s"%file_name)
        #self.__print_opening_unicode( event, "CreateFileW", lpFileName )
        self.CreateFileW_Queue.put(file_name)
    def post_CreateFileW(self,event,retval):
        try:
            if not self.CreateFileW_Queue.empty():
                self.file_map[int(retval)] = {'file_name':self.CreateFileW_Queue.get(),'offset':0,'ReadBuffer':0,'ReadLength':0}
                self.CreateFileW_Queue.task_done()
            else:
                logging.debug("CreateFileW Error! No Handle!")
        except:
            print "Bind CreateFileError, tmp = %s, retval = %d"%(tmp,retval)

#WriteFile
    def pre_WriteFile( self, event, ra, hFile, lpBuffer,
             nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
        #print "WriteFile: Filename: %s, Handle:%08d, lpBuffer:%016x, nNumberOfBytesToWrite:%-d, offset:%d"%(self.file_map[hFile]['file_name'],hFile, lpBuffer, nNumberOfBytesToWrite,self.file_map[hFile]['offset'])
        try:
            logging.debug("WriteFile: Filename: %s,WriteLength:%-d, Content:%s "%(self.file_map[hFile]['file_name'], nNumberOfBytesToWrite, event.get_process().peek_string(lpBuffer,dwMaxSize=nNumberOfBytesToWrite)))
        except:
            try:
                logging.debug("WriteFile: Filename: %s,WriteLength:%-d, Content:%s "%(self.file_map[hFile]['file_name'], nNumberOfBytesToWrite, event.get_process().peek_string(lpBuffer,fUnicode=True,dwMaxSize=nNumberOfBytesToWrite)))
            except:
                try:
                    logging.debug("WriteFile: Filename: %s,WriteLength:%-d, Content:%s "%(self.file_map[hFile]['file_name'], nNumberOfBytesToWrite, self.__print__hex(event, lpBuffer,nNumberOfBytesToWrite)))
                except:
                    logging.debug("WriteFile Error! Invilid Handle:%d"%hFile)
        #print event.get_process().peek_string(lpBuffer,dwMaxSize=nNumberOfBytesToWrite)
        #print "\n\n"
        self.file_map[hFile]['offset'] += nNumberOfBytesToWrite
    def post_WriteFile(self,event,retval):
        pass

#ReadFile
    def pre_ReadFile(self,event,ra,hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped):
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
        try:
            if not self.ReadFile_Queue.empty():
                tmp_handle = self.ReadFile_Queue.get()
                self.ReadFile_Queue.task_done()
                read_size = event.get_process().peek_int(self.file_map[tmp_handle]['ReadLength'])
                #print "Filename:%s, Readsize:%d, Buffer:%d"%(self.file_map[self.tmp_handle]['file_name'],read_size,self.file_map[self.tmp_handle]['ReadBuffer'])
                logging.debug("ReadFile: Filename:%s, Readsize:%d"%(self.file_map[tmp_handle]['file_name'],read_size))
            else:
                logging.debug("ReadFile Error! No Handle!")
        except:
            logging.debug("ReadFile Error! Handle:%d"%tmp_handle)


#CreateProcessA
    def pre_CreateProcessA(self, event, ra, lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
        logging.debug("CreateProcess:%s, CommandLine:%s"%(event.get_process().peek_string(lpApplicationName), event.get_process().peek_string(lpCommandLine)))


#CreateProcessW   
    def pre_CreateProcessW(self, event, ra, lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
        logging.debug("CreateProcess:%s, CommandLine:%s"%(event.get_process().peek_string(lpApplicationName,fUnicode = True), event.get_process().peek_string(lpCommandLine, fUnicode = True)))


#CreateThread
    def pre_CreateThread(self,event, ra, lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
        self.CreateThread_Queue.put({'StartAddress':hex(int(event.get_process().peek_uint(lpStartAddress))), 'Parameter': lpParameter})
    def post_CreateThread(self,event, retval):
        da = self.CreateThread_Queue.get()
        self.CreateThread_Queue.task_done()
        da['Handle'] = retval
        try:
            logging.debug('CreateThread:%s, StartAddress:%s, Parameter:%s'%(da['Handle'], da['StartAddress'], event.get_process().peek_string(da['Parameter'])))
        except:
            try:
                logging.debug('CreateThread:%s, StartAddress:%s, Parameter:%s'%(da['Handle'], da['StartAddress'], event.get_process().peek_string(da['Parameter'],fUnicode = True)))
            except:
                try:
                    logging.debug('CreateThread:%s, StartAddress:%s, Parameter:%s'%(da['Handle'], da['StartAddress'], self.__print__hex(self, event, da['Parameter'], 20)))
                except:
                    logging.debug("CreateThread Parameter Error")

#IsDebuggerPresent
    def pre_IsDebuggerPresent(self,event, ra):
        raw_input("Find Debugger")
    def post_IsDebuggerPresent(self, event, retval):
        print retval
        process = event.get_process()
        process.suspend()
        thread = event.get_thread()
        thread.set_register("Eax",0)
        raw_input(retval)

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
    

def simple_debugger(argv):

    # Instance a Debug object, passing it the event handler callback.
    #with Debug( MyEventHandler(), bKillOnExit = True ) as debug:
    with Debug( MyEventHandler(), bKillOnExit = True) as debug:
        try:

        # Start a new process for debugging.
            #debug.execv([b"C:/Users/hjc/Desktop/telegram/Telegram.exe"], bBreakOnEntryPoint=True)
            debug.execv(argv[0], bBreakOnEntryPoint=True)

        # Wait for the debugee to finish.
            debug.loop()
        except:
            print sys.exc_info()[1]

    # Stop the debugger.
        finally:
            debug.stop()


