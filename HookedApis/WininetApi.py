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

    #WininetMultiThreadsTmp
    InternetConnectA_Queue = Queue()
    InternetConnectW_Queue = Queue()


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

