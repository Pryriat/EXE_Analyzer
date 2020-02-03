from winappdbg.win32 import *
from winappdbg import *
from Hooking import *
from FileApi import file_map
import sys
import logging
import ctypes
from Queue import Queue

file_map = {}
internet_map={}
tmp = ''
tmp_handle = 0

#WininetMultiThreadsTmp
InternetConnectA_Queue = Queue()
InternetConnectW_Queue = Queue()
HttpQueryInfoA_Queue = Queue()
HttpQueryInfoW_Queue = Queue()
FtpOpenFileA_Queue = Queue()
FtpOpenFileW_Queue = Queue()

#WininetApis
#InternetOpenA
def MyPreInternetOpenA(event, ra, lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags):
    if FuncEnable['InternetOpenA']:
        try:
            proc = event.get_process()
            logging.debug("InternetOpenA->CallingEntry:%s, Proxy:%s, ProxyBpass:%s"%(proc.peek_string(lpszAgent), proc.peek_string(lpszProxy), proc.peek_string(lpszProxyBypass)))
        except:
            logging.debug("InternetOpenA Error!")
def MyPostInternetOpenA(event, retval):
    pass

#InternetOpenW
def MyPreInternetOpenW(event, ra, lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags):
    if FuncEnable['InternetOpenW']:
        try:
            proc = event.get_process()
            logging.debug("InternetOpenW->CallingEntry:%s, Proxy:%s, ProxyBpass:%s"%(proc.peek_string(lpszAgent,fUnicode=True), proc.peek_string(lpszProxy,fUnicode=True), proc.peek_string(lpszProxyBypass,fUnicode=True)))
        except:
            logging.debug("InternetOpenW Error!")
def MyPostInternetOpenW(event, retval):
    pass

#InternetOpenUrlA
def MyPreInternetOpenUrlA(event, ra, hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext):
    if FuncEnable['InternetOpenUrlA']:
        try:
            proc = event.process()
            logging.debug("InternetOpenUrlA->Url:%s, Headers:%s"%(proc.peek_string(lpszUrl), proc.peek_string(lpszHeaders)))
        except:
            logging.debug("InternetOpenUrlA Error!")
def MyPostInternetOpenUrlA(event, retval):
    pass

#InternetOpenUrlW
def MyPreInternetOpenUrlW(event, ra, hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext):
    if FuncEnable['InternetOpenUrlW']:
        try:
            proc = event.process()
            logging.debug("InternetOpenUrlW->Url:%s, Headers:%s"%(proc.peek_string(lpszUrl,fUnicode=True), proc.peek_string(lpszHeaders,fUnicode=True)))
        except:
            logging.debug("InternetOpenUrlW Error!")
def MyPostInternetOpenUrlW(event, retval):
    pass

#InternetConnectA
def MyPreInternetConnectA(event, ra, hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext):
    if FuncEnable['InternetConnectA']:
        try:
            proc = event.get_process()
            logging.debug("InternetConnectA->ServerName:%s, UserName:%s, Password:%s"%(proc.peek_string(lpszServerName), proc.peek_string(lpszUserName), proc.peek_string(lpszPassword)))
            InternetConnectA_Queue.put(proc.peek_string(lpszServerName))
        except:
            logging.debug("InternetConnectA Error!")
def MyPostInternetConnectA(event, retval):
    if FuncEnable['InternetConnectA']:
        try:
            if not InternetConnectA_Queue.empty():
                server = InternetConnectA_Queue.get()
                InternetConnectA_Queue.task_done()
                internet_map[int(retval)] = server
        except:
            logging.debug("InternetConnectA Error!")

#InternetConnectW
def MyPreInternetConnectW(event, ra, hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext):
    if FuncEnable['InternetConnectW']:
        try:
            proc = event.get_process()
            logging.debug("InternetConnectW->ServerName:%s, UserName:%s, Password:%s"%(proc.peek_string(lpszServerName, fUnicode=True), proc.peek_string(lpszUserName, fUnicode=True), proc.peek_string(lpszPassword, fUnicode=True)))
            InternetConnectW_Queue.put(proc.peek_string(lpszServerName,fUnicode=True))
        except:
            logging.debug("InternetConnectW Error!")
def MyPostInternetConnectW(event, retval):
    if FuncEnable['InternetConnectW']:
        try:
            if not InternetConnectW_Queue.empty():
                server = InternetConnectW_Queue.get()
                InternetConnectW_Queue.task_done()
                internet_map[int(retval)] = server
        except:
            logging.debug("InternetConnectW Error!")

#HttpOpenRequestA
def MyPreHttpOpenRequestA(event, ra, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext):
    if FuncEnable['HttpOpenRequestA']:
        try:
            proc = event.get_process()
            logging.debug("HttpOpenRequestA->Object:%s, Method:%s, Version:%s, Referrer:%s"%(internet_map[int(hConnect)]+proc.peek_string(lpszObjectName), proc.peek_string(lpszVerb), proc.peek_string(lpszVersion), proc.peek_string(lpszReferrer)))
        except:
            logging.debug("HttpOpenRequestA Error!")
def MyPostHttpOpenRequestA(event, retval):
    pass

#HttpOpenRequestW
def MyPreHttpOpenRequestW(event, ra, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext):
    if FuncEnable['HttpOpenRequestW']:
        try:
            proc = event.get_process()
            logging.debug("HttpOpenRequestW->Object:%s, Method:%s, Version:%s, Referrer:%s"%(internet_map[int(hConnect)]+proc.peek_string(lpszObjectName,fUnicode=True), proc.peek_string(lpszVerb,fUnicode=True), proc.peek_string(lpszVersion,fUnicode=True), proc.peek_string(lpszReferrer,fUnicode=True)))
        except:
            logging.debug("HttpOpenRequestW Error!")
def MyPostHttpOpenRequestW(event, retval):
    pass

#HttpQueryInfoA
def MyPreHttpQueryInfoA(event, ra, hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex):
    if FuncEnable['HttpQueryInfoA']:
        try:
            HttpQueryInfoA_Queue.put([hRequest, lpBuffer, lpdwBufferLength])
        except:
            logging.debug("HttpQueryInfoA Error!")
def MyPostHttpQueryInfoA(event, retval):
    if retval and FuncEnable['HttpQueryInfoA']:
        try:
            if not HttpQueryInfoA_Queue.empty():
                tmp = HttpQueryInfoA_Queue.get()
                HttpQueryInfoA_Queue.task_done()
            else:
                return
            proc = event.get_process()
            try:
                context = proc.peek_string(tmp[1],dwMaxSize = proc.peek_int(tmp[2])).encode("ascii")
            except:
                context = __print__hex(event, tmp[1], tmp[2])
            logging.debug("HttpQueryInfoA->Result:%s"%conetxt)
        except:
            logging.debug("HttpQueryInfoA Error!")

#HttpQueryInfoW
def MyPreHttpQueryInfoW(event, ra, hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex):
    if FuncEnable['HttpQueryInfoW']:
        try:
            HttpQueryInfoW_Queue.put([hRequest, lpBuffer, lpdwBufferLength])
        except:
            logging.debug("HttpQueryInfoW Error!")
def MyPostHttpQueryInfoA(event, retval):
    if retval and FuncEnable['HttpQueryInfoW']::
        try:
            if not HttpQueryInfoW_Queue.empty():
                tmp = HttpQueryInfoW_Queue.get()
                HttpQueryInfoW_Queue.task_done()
            else:
                return
            proc = event.get_process()
            try:
                context = proc.peek_string(tmp[1], fUnicode = True, dwMaxSize = proc.peek_int(tmp[2]))
            except:
                context = __print__hex(event, tmp[1], tmp[2])
            logging.debug("HttpQueryInfoW->Result:%s"%conetxt)
        except:
            logging.debug("HttpQueryInfoW Error!")

#HttpSendRequestA
def MyPreHttpSendRequestA(event, ra, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
    if FuncEnable['HttpSendRequestA']:
        try:
            proc = event.get_process()
            try:
                jud = proc.peek_string(lpszHeaders, dwMaxSize=dwHeadersLength).encode('ascii')
            except:
                jud = __print__hex(event, lpszHeaders, dwHeadersLength)
            logging.debug("HttpSendRequestA->Context:%s"%jud)
        except:
            logging.debug("HttpSendRequestA Error!")
def MyPostHttpSendRequestA(event, retval):
    pass

#HttpSendRequestW
def MyPreHttpSendRequestW(event, ra, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
    if FuncEnable['HttpSendRequestW']:
        try:
            proc = event.get_process()
            try:
                jud = proc.peek_string(lpszHeaders, dwMaxSize=dwHeadersLength,fUnicode=True)
            except:
                jud = __print__hex(event, lpszHeaders, dwHeadersLength)
            logging.debug("HttpSendRequestW->Context:%s"%jud)
        except:
            logging.debug("HttpSendRequestW Error!")

def MyPostHttpSendRequestW(event, retval):
    pass

#FtpCommandA
def MyPreFtpCommandA(event, ra, hConnect, fExpectResponse, dwFlags, lpszCommand, dwContext, phFtpCommand):
    if FuncEnable['FtpCommandA']:
        try:
            proc = event.get_process()
            try:
                jud = proc.peek_string(lpszCommand).encode('ascii')
            except:
                jud = __print__hex(event, lpszCommand)
            logging.debug("FtpCommandA->Server:%s, Command:%s"%(internet_map[int(hConnect)], jud))
        except:
            logging.debug("FtpCommandA Error!")
def MyPostFtpCommandA(event, retval):
    pass

#FtpCommandW
def MyPreFtpCommandW(event, ra, hConnect, fExpectResponse, dwFlags, lpszCommand, dwContext, phFtpCommand):
    if FuncEnable['FtpCommandA']:
        try:
            proc = event.get_process()
            try:
                jud = proc.peek_string(lpszCommand,fUnicode=True)
            except:
                jud = __print__hex(event, lpszCommand)
            logging.debug("FtpCommandW->Server:%s, Command:%s"%(internet_map[int(hConnect)], jud))
        except:
            logging.debug("FtpCommandW Error!")
def MyPostFtpCommandW(event, retval):
    pass

#FtpGetFileA
def MyPreFtpGetFileA(event, ra, hConnect, lpszRemoteFile, lpszNewFile, fFailIfExists, dwFlagsAndAttributes, dwFlags, dwContext):
    if FuncEnable['FtpGetFileA']:
        try:
            proc = event.get_process()
            try:
                RF = proc.peek_string(lpszRemoteFile).encode('ascii')
                NF = proc.peek_string(lpszNewFile).encode('ascii')
            except:
                RF = __print__hex(event, lpszRemoteFile)
                NF = __print__hex(event, lpszNewFile)
            logging.debug("FtpGetFileA->Server:%s, RemoteFile:%s, NewFile:%s"%(internet_map[int(hConnect)], RF, NF))
        except:
            logging.debug("FtpGetFileA Error!")
def MyPostFtpGetFileA(event, retval):
    pass

#FtpGetFileW
def MyPreFtpGetFileW(event, ra, hConnect, lpszRemoteFile, lpszNewFile, fFailIfExists, dwFlagsAndAttributes, dwFlags, dwContext):
    if FuncEnable['FtpGetFileW']:
        try:
            proc = event.get_process()
            try:
                RF = proc.peek_string(lpszRemoteFile,fUnicode=True)
                NF = proc.peek_string(lpszNewFile,fUnicode=True)
            except:
                RF = __print__hex(event, lpszRemoteFile)
                NF = __print__hex(event, lpszNewFile)
            logging.debug("FtpGetFileW->Server:%s, RemoteFile:%s, NewFile:%s"%(internet_map[int(hConnect)], RF, NF))
        except:
            logging.debug("FtpGetFileW Error!")
def MyPostFtpGetFileW(event, retval):
    pass

#FtpOpenFileA
def MyPreFtpOpenFileA(event, ra, hConnect, lpszFileName, dwAccess, dwFlags, dwContext):
    if FuncEnable['FtpOpenFileA']:
        try:
            proc = event.get_process()
            try:
                jud = proc.peek_string(lpszFileName).encode('ascii')
            except:
                jud = __print__hex(event, lpszFileName)
            logging.debug("FtpOpenFileA->Server:%s, File:%s"%(internet_map[int(hConnect), jud]))
            FtpOpenFileA_Queue.put(jud)
        except:
            logging.debug("FtpOpenFileA Error!")
def MyPostFtpOpenFileA(event, retval):
    if retval:
        try:
            if not FtpOpenFileA_Queue.empty():
                tmp = FtpOpenFileA_Queue.get()
                FtpOpenFileA_Queue.task_done()
                file_map[int(retval)] = {'file_name':tmp,'offset':0,'ReadBuffer':0,'ReadLength':0}
        except:
            logging.debug("FtpOpenFileA Error!")

#FtpOpenFileW
def MyPreFtpOpenFileW(event, ra, hConnect, lpszFileName, dwAccess, dwFlags, dwContext):
    if FuncEnable['FtpOpenFileW']:
        try:
            proc = event.get_process()
            try:
                jud = proc.peek_string(lpszFileName,fUnicode=True)
            except:
                jud = __print__hex(event, lpszFileName)
            logging.debug("FtpOpenFileA->Server:%s, File:%s"%(internet_map[int(hConnect), jud]))
            FtpOpenFileW_Queue.put(jud)
        except:
            logging.debug("FtpOpenFileW Error!")
def MyPostFtpOpenFileW(event, retval):
    if retval:
        try:
            if not FtpOpenFileW_Queue.empty():
                tmp = FtpOpenFileW_Queue.get()
                FtpOpenFileW_Queue.task_done()
                file_map[int(retval)] = {'file_name':tmp,'offset':0,'ReadBuffer':0,'ReadLength':0}
        except:
            logging.debug("FtpOpenFileW Error!")

# Some helper private methods

def __print__hex(event, pointer, len=20):
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

