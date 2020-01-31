from winappdbg.win32 import *
from winappdbg import *
from Hooking import *
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

# Some helper private methods

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

