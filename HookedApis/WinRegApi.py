from winappdbg.win32 import *
from winappdbg import *
from Hooking import *
import sys
import logging
import ctypes
from Queue import Queue

class WinRegApi():
    file_map = {}
    internet_map={}
    tmp = ''
    tmp_handle = 0
    

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

    def uint(self, num):
        return int(num)&0xffffffff
