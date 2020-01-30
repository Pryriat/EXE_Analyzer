from winappdbg.win32 import *
from winappdbg import *
from Hooking import *
import sys
import logging
import ctypes
from Queue import Queue

class FileApi():
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