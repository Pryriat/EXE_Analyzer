from winappdbg.win32 import *
from winappdbg import *
from Hooking import *
import sys
import logging
import ctypes
from Queue import Queue


#WinRegApis
#RegCreateKeyA
def MyPreRegCreateKeyA(event, ra, hKey, lpSubKey, phkResult):
    if FuncEnable['RegCreateKeyA']:
        try:
            logging.debug("RegCreateKeyA->KeyHandle:%s, CreateKey:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey)))
        except:
            logging.debug("RegCreateKeyA Error!")
def MyPostRegCreateKeyA(event, retval):
    pass

#RegCreateKeyW
def MyPreRegCreateKeyW(event, ra, hKey, lpSubKey, phkResult):
    if FuncEnable['RegCreateKeyW']:
        try:
            logging.debug("RegCreateKeyW->KeyHandle:%s, CreateKey:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True)))
        except:
            logging.debug("RegCreateKeyW Error!")
def MyPostRegCreateKeyW(event, retval):
    pass

#RegCreateKeyExA
def MyPreRegCreateKeyExA(event, ra, hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition):
    if FuncEnable['RegCreateKeyExA']:
        try:
            logging.debug("RegCreateKeyExA->KeyHandle:%s, CreateKey:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey)))
        except:
            logging.debug("RegCreateKeyExA Error!")
def MyPostRegCreateKeyExA(event, retval):
    pass

#RegCreateKeyExW
def MyPreRegCreateKeyExW(event, ra, hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition):
    if FuncEnable['RegCreateKeyExW']:
        try:
            logging.debug("RegCreateKeyExW->KeyHandle:%s, CreateKey:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True)))
        except:
            logging.debug("RegCreateKeyExW Error!")
def MyPostRegCreateKeyExW(event, retval):
    pass

#RegOpenKeyA
def MyPreRegOpenKeyA(event, ra, hKey, lpSubKey, phkResult):
    if FuncEnable['RegOpenKeyA']:
        try:
            logging.debug("RegOpenKeyA->KeyHandle:%s, OpenKey:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey)))
        except:
            logging.debug("RegOpenKeyA Error!")
def MyPostRegOpenKeyA(event, retval):
    pass

#RegOpenKeyExA
def MyPreRegOpenKeyExA(event, ra, hKey, lpSubKey, ulOptions, samDesired, phkResult):
    if FuncEnable['RegOpenKeyExA']:
        try:
            logging.debug("RegOpenKeyExA->KeyHandle:%s, OpenKey:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey)))
        except:
            logging.debug("RegOpenKeyExA Error!")
def MyPostRegOpenKeyExA(event, retval):
    pass

#RegOpenKeyW
def MyPreRegOpenKeyW(event, ra, hKey, lpSubKey, phkResult):
    if FuncEnable['RegOpenKeyW']:
        try:
            logging.debug("RegOpenKeyW->KeyHandle:%s, OpenKey:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True)))
        except:
            logging.debug("RegOpenKeyW Error!")
def MyPostRegOpenKeyW(event, retval):
    pass

#RegOpenKeyExW
def MyPreRegOpenKeyExW(event, ra, hKey, lpSubKey, ulOptions, samDesired,phkResult):
    if FuncEnable['RegOpenKeyExW']:
        try:
            logging.debug("RegOpenKeyExW ->KeyHandle:%s, OpenKey:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True)))
        except:
            logging.debug("RegOpenKeyExW Error!")
def MyPostRegOpenKeyExW(event, retval):
    pass


#RegDeleteKeyA
def MyPreRegDeleteKeyA(event, ra, hKey, lpSubKey):
    if FuncEnable['RegDeleteKeyA']:
        try:
            logging.debug("RegDeleteKeyA->KeyHandle:%s, DeleteKey:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey)))
        except:
            logging.debug("RegDeleteKeyA Error!")
def MyPostRegDeleteKeyA(event, retval):
    pass

#RegDeleteKeyW
def MyPreRegDeleteKeyW(event, ra, hKey, lpSubKey):
    if FuncEnable['RegDeleteKeyW']:
        try:
            logging.debug("RegDeleteKeyW->KeyHandle:%s, DeleteKey:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True)))
        except:
            logging.debug("RegDeleteKeyW Error!")
def MyPostRegDeleteKeyW(event, retval):
    pass


#RegDeleteValueA
def MyPreRegDeleteValueA(event, ra, hKey, lpValueName):
    if FuncEnable['RegDeleteValueA']:
        try:
            logging.debug("RegDeleteValueA->KeyHandle:%s, DeleteValue:%s"%(uint(hKey), event.get_process().peek_string(lpValueName)))
        except:
            logging.debug("RegDeleteValueA Error!")
def MyPostRegDeleteValueA(event, retval):
    pass

#RegDeleteValueW
def MyPreRegDeleteValueW(event, ra, hKey, lpValueName):
    if FuncEnable['RegDeleteValueW']:
        try:
            logging.debug("RegDeleteValueW->KeyHandle:%s, DeleteValue:%s"%(uint(hKey), event.get_process().peek_string(lpValueName,fUnicode=True)))
        except:
            logging.debug("RegDeleteValueW Error!")
def MyPostRegDeleteValueW(event, retval):
    pass

#RegGetValueA
def MyPreRegGetValueA(event, ra, hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
    if FuncEnable['RegGetValueA']:
        try:
            logging.debug("RegGetValueA->KeyHandle:%s, Key:%s, GetValueName:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey),event.get_process().peek_string(lpValue)))
        except:
            logging.debug("RegGetValueA Error!")
def MyPostRegGetValueA(event, ra):
    pass

#RegGetValueW
def MyPreRegGetValueW(event, ra, hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
    if FuncEnable['RegGetValueW']:
        try:
            logging.debug("RegGetValueW->KeyHandle:%s, Key:%s, GetValueName:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True),event.get_process().peek_string(lpValue,fUnicode=True)))
        except:
            logging.debug("RegGetValueW Error!")
def MyPostRegGetValueW(event, ra):
    pass

#RegLoadKeyA
def MyPreRegLoadKeyA(event, ra, hKey, lpSubKey, lpFile):
    if FuncEnable['RegLoadKeyA']:
        try:
            logging.debug("RegLoadKeyA->KeyHandle:%s, Key:%s, LoadFile:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey),event.get_process().peek_string(lpFile)))
        except:
            logging.debug("RegLoadKeyA Error!")
def MyPostRegLoadKeyA(event, retval):
    pass

#RegLoadKeyW
def MyPreRegLoadKeyW(event, ra, hKey, lpSubKey, lpFile):
    if FuncEnable['RegLoadKeyW']:
        try:
            logging.debug("RegLoadKeyW->KeyHandle:%s, Key:%s, LoadFile:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True),event.get_process().peek_string(lpFile,fUnicode=True)))
        except:
            logging.debug("RegLoadKeyW Error!")
def MyPostRegLoadKeyw(event, retval):
    pass

#RegSetKeyValueA
def MyPreRegSetKeyValueA(event, ra, hKey, lpSubKey, lpValueName, dwType, lpData, cbData):
    if FuncEnable['RegSetKeyValueA']:
        try:
            logging.debug("RegSetKeyValueA->KeyHandle:%s, Key:%s, UpdateValueName:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey),event.get_process().peek_string(lpValueName)))
        except:
            logging.debug("RegSetKeyValueA Error!")
def MyPostRegSetKeyValueA(event, retval):
    pass

#RegSetKeyValueW
def MyPreRegSetKeyValueW(event, ra, hKey, lpSubKey, lpValueName, dwType, lpData, cbData):
    if FuncEnable['RegSetKeyValueW']:
        try:
            logging.debug("RegSetKeyValueW->KeyHandle:%s, Key:%s, UpdateValueName:%s"%(uint(hKey), event.get_process().peek_string(lpSubKey,fUnicode=True),event.get_process().peek_string(lpValueName,fUnicode=True)))
        except:
            logging.debug("RegSetKeyValueW Error!")
def MyPostRegSetKeyValueW(event, retval):
    pass

#RegSetValueExA
def MyPreRegSetValueExA(event, ra, hKey, lpValueName, Reserved, dwType, lpData, cbData):
    if FuncEnable['RegSetValueExA']:
        try:
            logging.debug("RegSetValueExA->KeyHandle:%s, UpdateValueName:%s"%(uint(hKey) ,event.get_process().peek_string(lpValueName)))
        except:
            logging.debug("RegSetKeyValueExA Error!")
def MyPostRegSetValueExA(event, retval):
    pass

#RegSetValueExW
def MyPreRegSetValueExW(event, ra, hKey, lpValueName, Reserved, dwType, lpData, cbData):
    if FuncEnable['RegSetValueExW']:
        try:
            logging.debug("RegSetValueExW->KeyHandle:%s, UpdateValueName:%s"%(uint(hKey) ,event.get_process().peek_string(lpValueName, fUnicode=True)))
        except:
            logging.debug("RegSetKeyValueExW Error!")
def MyPostRegSetValueExW(event, retval):
    pass

def uint(num):
    return int(num)&0xffffffff
