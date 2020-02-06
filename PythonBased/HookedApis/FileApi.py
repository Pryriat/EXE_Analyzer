from winappdbg.win32 import *
from winappdbg import *
from Hooking import *
import sys
import logging
import ctypes
from Queue import Queue

file_map={}

#FileMultiThreadsTmp
CreateFileA_Queue = Queue()
CreateFileW_Queue = Queue()
ReadFile_Queue = Queue()
WriteFile_Queue = Queue()
MoveFileA_Queue = Queue()
MoveFileW_Queue = Queue()
MoveFileExA_Queue = Queue()
MoveFileExW_Queue = Queue()

#FileApis
#CreateFileA
def MyPreCreateFileA(event, ra, lpFileName, dwDesiredAccess,
    dwShareMode, lpSecurityAttributes, dwCreationDisposition,
    dwFlagsAndAttributes, hTemplateFile ):
    if FuncEnable['CreateFileA']:
        file_name = event.get_process().peek_string(lpFileName)
        logging.debug("CreateFileA->FileName:%s"%file_name)
        CreateFileA_Queue.put(file_name)
def MyPostCreateFileA(event,retval):
    if FuncEnable['CreateFileA']:
        try:
            if not CreateFileA_Queue.empty():
                tmp = CreateFileA_Queue.get()
                CreateFileA_Queue.task_done()
                file_map[int(retval)] = {'file_name':tmp,'offset':0,'ReadBuffer':0,'ReadLength':0}
            else:
                logging.debug("CreateFileA Error! No Handle!")
        except:
            print "Bind CreateFileError, tmp = %s, retval = %d"%(tmp,retval)

#CreateFileW
def MyPreCreateFileW(event, ra, lpFileName, dwDesiredAccess,
    dwShareMode, lpSecurityAttributes, dwCreationDisposition,
    dwFlagsAndAttributes, hTemplateFile ):
    if FuncEnable['CreateFileW']:
        file_name = event.get_process().peek_string(lpFileName, fUnicode = True )
        logging.debug("CreateFileW->FileName:%s"%file_name)
        CreateFileW_Queue.put(file_name)
def MyPostCreateFileW(event,retval):
    if FuncEnable['CreateFileW']:
        try:
            if not CreateFileW_Queue.empty():
                tmp = CreateFileW_Queue.get()
                CreateFileW_Queue.task_done()
                file_map[int(retval)] = {'file_name':tmp,'offset':0,'ReadBuffer':0,'ReadLength':0}
            else:
                logging.debug("CreateFileW Error! No Handle!")
        except:
            print "Bind CreateFileError, tmp = %s, retval = %d"%(tmp,retval)

#WriteFile
def MyPreWriteFile(event, ra, hFile, lpBuffer,
    nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
    if FuncEnable['WriteFile']:
        try:
            jud = event.get_process().peek_string(lpBuffer,dwMaxSize=nNumberOfBytesToWrite).encode("ascii")
            #logging.debug("WriteFile->Filename: %s,WriteLength:%-d, Content:%s "%(file_map[hFile]['file_name'], nNumberOfBytesToWrite, event.get_process().peek_string(lpBuffer,dwMaxSize=nNumberOfBytesToWrite)))
            logging.debug("WriteFile->Filename: %s,WriteLength:%-d"%(file_map[hFile]['file_name'], nNumberOfBytesToWrite))
        except:
            try:
                logging.debug("WriteFile->Filename: %s,WriteLength:%-d"%(file_map[hFile]['file_name'], nNumberOfBytesToWrite))
            except:
                logging.debug("WriteFile Error! Invilid Handle:%s"%hFile)    
        try:
            file_map[hFile]['offset'] += nNumberOfBytesToWrite
        except:
            logging.debug("WriteFile Error! Invilid Handle:%s"%hFile) 
def MyPostWriteFile(event,retval):
    pass

#ReadFile
def MyPreReadFile(event,ra,hFile,lpBuffer,nNumberOfBytesToRead,
    lpNumberOfBytesRead,lpOverlapped):
    if FuncEnable['ReadFile']:
        try:
            file_map[hFile]['ReadBuffer'] = lpBuffer
            file_map[hFile]['ReadLength'] = lpNumberOfBytesRead
            file_map[hFile]['offset']+=nNumberOfBytesToRead
        except:
            logging.debug("Handle Error :%d"%hFile)
        ReadFile_Queue.put(hFile,timeout = 1)
def MyPostReadFile(event,retval):
    if FuncEnable['ReadFile']:
        try:
            if not ReadFile_Queue.empty():
                tmp_handle = ReadFile_Queue.get()
                ReadFile_Queue.task_done()
                read_size = event.get_process().peek_int(file_map[tmp_handle]['ReadLength'])
                logging.debug("ReadFile->Filename:%s, Readsize:%d"%(file_map[tmp_handle]['file_name'],read_size))
            else:
                logging.debug("ReadFile Error! No Handle!")
        except:
            logging.debug("ReadFile Error! Handle:%d"%tmp_handle)

#MoveFileA
def MyPreMoveFileA(event, ra, lpExistingFileName, lpNewFileName):
    if FuncEnable['MoveFileA']:
        proc = event.get_process()
        MoveFileA_Queue.put([proc.peek_string(lpExistingFileName), proc.peek_string(lpNewFileName)])
def MyPostMoveFileA(event, retval):
    if FuncEnable['MoveFileA']:
        try:
            if not MoveFileA_Queue.empty():
                    tmp = MoveFileA_Queue.get()
                    MoveFileA_Queue.task_done()
                    logging.debug("MoveFileA->From %s to %s, IsSucceed:%s"%(tmp[0], tmp[1], retval))
        except:
            logging.debug("MoveFileA Error!")

#MoveFileW
def MyPreMoveFileW(event, ra, lpExistingFileName, lpNewFileName):
    if FuncEnable['MoveFileW']:
        proc = event.get_process()
        MoveFileW_Queue.put([proc.peek_string(lpExistingFileName,fUnicode=True), proc.peek_string(lpNewFileName,fUnicode=True)])
def MyPostMoveFileW(event, retval):
    if FuncEnable['MoveFileW']:
        try:
            if not MoveFileW_Queue.empty():
                    tmp = MoveFileW_Queue.get()
                    MoveFileW_Queue.task_done()
                    logging.debug("MoveFileW->From %s to %s, IsSucceed:%s"%(tmp[0], tmp[1], retval))
        except:
            logging.debug("MoveFileW Error!")

#MoveFileExA
def MyPreMoveFileExA(event, ra, lpExistingFileName, lpNewFileName, dwFlags):
    if FuncEnable['MoveFileExA']:
        proc = event.get_process()
        MoveFileExA_Queue.put([proc.peek_string(lpExistingFileName), proc.peek_string(lpNewFileName)])
def MyPostMoveFileExA(event, retval):
    if FuncEnable['MoveFileExA']:
        try:
            if not MoveFileExA_Queue.empty():
                    tmp = MoveFileExA_Queue.get()
                    MoveFileExA_Queue.task_done()
                    logging.debug("MoveFile->From %s to %s, IsSucceed:%s"%(tmp[0], tmp[1], retval))
        except:
            logging.debug("MoveFileExA Error!")

#MoveFileExW
def MyPreMoveFileExW(event, ra, lpExistingFileName, lpNewFileName, dwFlags):
    if FuncEnable['MoveFileExW']:
        proc = event.get_process()
        MoveFileExW_Queue.put([proc.peek_string(lpExistingFileName, fUnicode=True), proc.peek_string(lpNewFileName, fUnicode=True)])
def MyPostMoveFileExW(event, retval):
    if FuncEnable['MoveFileExW']:
        try:
            if not MoveFileExW_Queue.empty():
                    tmp = MoveFileExW_Queue.get()
                    MoveFileExW_Queue.task_done()
                    logging.debug("MoveFile->From %s to %s, IsSucceed:%s"%(tmp[0], tmp[1], retval))
        except:
            logging.debug("MoveFileExW Error!")