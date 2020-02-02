from winappdbg.win32 import *
from winappdbg import *
import sys
apihooking = {
        'kernel32.dll' : [
            #  Function              Parameters
            ( 'CreateFileA'          , (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE) ),
            ( 'CreateFileW'          , (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE) ),
            ( 'ReadFile'             , (HANDLE, PVOID, DWORD, PVOID, PVOID) ),
            ( 'ReadFileEx'           , (HANDLE, PVOID, DWORD, PVOID, PVOID) ),
            ( 'WriteFile'            , (HANDLE, PVOID, DWORD, PVOID, PVOID) ),
            ( 'WriteFileEx'          , (HANDLE, PVOID, DWORD, PVOID, PVOID) ),
            ( 'CreateProcessA'       , (PVOID, PVOID, PVOID, PVOID, BOOL, DWORD, PVOID, PVOID, PVOID, PVOID) ),
            ( 'CreateProcessW'       , (PVOID, PVOID, PVOID, PVOID, BOOL, DWORD, PVOID, PVOID, PVOID, PVOID) ),
            ( 'CreateThread'         , (PVOID, DWORD, PVOID, PVOID, DWORD, PVOID)),
            ( 'IsDebuggerPresent'    , () ),
            ( 'MoveFileA'            , (PVOID, PVOID) ),
            ( 'MoveFileW'            , (PVOID, PVOID) ),
            ( 'MoveFileExA'          , (PVOID, PVOID, DWORD) ),
            ( 'MoveFileExW'          , (PVOID, PVOID, DWORD) ),
            ( 'OpenProcess'          , (DWORD, BOOL, DWORD) ),
            ( 'WriteProcessMemory'   , (HANDLE, PVOID, PVOID, DWORD, DWORD) ),
            ( 'WinExec'              , (PVOID, DWORD) ),
            ( 'CreateRemoteThread'   , (HANDLE, PVOID, DWORD, PVOID, PVOID, DWORD, PVOID) ),
            ( 'CreateRemoteThreadEx' , (HANDLE, PVOID, DWORD, PVOID, PVOID, DWORD, PVOID, PVOID) )
        ],
        'advapi32.dll' : [
            # Function               Parameters
            ( 'RegOpenKeyA'          , (HANDLE, PVOID, PVOID) ),
            ( 'RegOpenKeyW'          , (HANDLE, PVOID, PVOID) ),
            ( 'RegOpenKeyExA'        , (HANDLE, PVOID, DWORD, ULONG, PVOID) ),
            ( 'RegOpenKeyExW'        , (HANDLE, PVOID, DWORD, ULONG, PVOID) ),
            ( 'RegCreateKeyA'        , (HANDLE, PVOID, PVOID) ),
            ( 'RegCreateKeyW'        , (HANDLE, PVOID, PVOID) ),
            ( 'RegCreateKeyExA'      , (HANDLE, PVOID, DWORD, PVOID, DWORD, ULONG, PVOID, PVOID, PVOID) ),
            ( 'RegCreateKeyExW'      , (HANDLE, PVOID, DWORD, PVOID, DWORD, ULONG, PVOID, PVOID, PVOID) ),
            ( 'RegDeleteKeyA'        , (HANDLE, PVOID) ),
            ( 'RegDeleteKeyW'        , (HANDLE, PVOID) ),
            ( 'RegGetValueA'         , (HANDLE, PVOID, PVOID, DWORD, PVOID, PVOID, PVOID) ),
            ( 'RegGetValueW'         , (HANDLE, PVOID, PVOID, DWORD, PVOID, PVOID, PVOID) ),
            ( 'RegLoadKeyA'          , (HANDLE, PVOID, PVOID) ),
            ( 'RegLoadKeyW'          , (HANDLE, PVOID, PVOID) ),
            ( 'RegSetKeyValueA'      , (HANDLE, PVOID, PVOID, DWORD, PVOID, DWORD) ),
            ( 'RegSetKeyValueW'      , (HANDLE, PVOID, PVOID, DWORD, PVOID, DWORD) ),
            ( 'RegSetValueExA'       , (HANDLE, PVOID, DWORD, DWORD, PVOID, DWORD) ),
            ( 'RegSetValueExW'       , (HANDLE, PVOID, DWORD, DWORD, PVOID, DWORD) )
        ],
        'wininet.dll' :[
            #Function                Parameters
            ( 'InternetOpenA'        , (PVOID, DWORD, PVOID, PVOID, DWORD) ),
            ( 'InternetOpenW'        , (PVOID, DWORD, PVOID, PVOID, DWORD) ),
            ( 'InternetOpenUrlA'     , (HANDLE, PVOID, PVOID, DWORD, DWORD, PVOID) ),
            ( 'InternetOpenUrlW'     , (HANDLE, PVOID, PVOID, DWORD, DWORD, PVOID) ),
            ( 'InternetConnectA'     , (HANDLE, PVOID, WORD, PVOID, PVOID, DWORD, DWORD, PVOID) ),
            ( 'InternetConnectW'     , (HANDLE, PVOID, WORD, PVOID, PVOID, DWORD, DWORD, PVOID) ),
            ( 'HttpOpenRequestA'     , (HANDLE, PVOID, PVOID, PVOID, PVOID, PVOID, DWORD, PVOID) ),
            ( 'HttpOpenRequestW'     , (HANDLE, PVOID, PVOID, PVOID, PVOID, PVOID, DWORD, PVOID) ),
            ( 'HttpQueryInfoA'       , (HANDLE, DWORD, PVOID, PVOID, PVOID) ),
            ( 'HttpQueryInfoW'       , (HANDLE, DWORD, PVOID, PVOID, PVOID) )
        ]
    }

FuncEnable = {
    #Kernel32.dll
    'CreateFileA'            :True,
    'CreateFileW'            :True,
    'ReadFile'               :True,
    'ReadFileEx'             :True,
    'WriteFile'              :True,
    'WriteFileEx'            :True,
    'CreateProcessA'         :True,
    'CreateProcessW'         :True,
    'CreateThread'           :True,
    'IsDebuggerPresent'      :True,
    'MoveFileA'              :True,
    'MoveFileW'              :True,
    'MoveFileExA'            :True,
    'MoveFileExW'            :True,
    'OpenProcess'            :True,
    'WriteProcessMemory'     :True,
    'WinExec'                :True,
    'CreateRemoteThread'     :True,
    'CreateRemoteThreadEx'   :True,
    
    #advapi32.dll
    'RegOpenKeyA'            :True,
    'RegOpenKeyW'            :True,
    'RegOpenKeyExA'          :True,
    'RegOpenKeyExW'          :True,
    'RegCreateKeyA'          :True,
    'RegCreateKeyW'          :True,
    'RegCreateKeyExA'        :True,
    'RegCreateKeyExW'        :True,
    'RegDeleteKeyA'          :True,
    'RegDeleteKeyW'          :True,
    'RegDeleteValueA'        :True,
    'RegDeleteValueW'        :True,
    'RegGetValueA'           :True,
    'RegGetValueW'           :True,
    'RegLoadKeyA'            :True,
    'RegLoadKeyW'            :True,
    'RegSetKeyValueA'        :True,
    'RegSetKeyValueW'        :True,
    'RegSetValueExA'         :True,
    'RegSetValueExW'         :True,

    #wininet.dll
    'InternetOpenA'          :True,
    'InternetOpenW'          :True,
    'InternetOpenUrlA'       :True,
    'InternetOpenUrlW'       :True,
    'InternetConnectA'       :True,
    'InternetConnectW'       :True,
    'HttpOpenRequestA'       :True,
    'HttpOpenRequestW'       :True,
    'HttpQueryInfoA'         :True,
    'HttpQueryInfoW'         :True
}