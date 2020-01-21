from winappdbg.win32 import *
from winappdbg import *
import sys
apihooking = {
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
            ( 'IsDebuggerPresent', ()),
            ( 'MoveFileA'       , (PVOID, PVOID)),
            ( 'MoveFileW'       , (PVOID, PVOID)),
            ( 'OpenProcess'     , (DWORD, BOOL, DWORD)),
            ( 'WriteProcessMemory', (HANDLE, PVOID, PVOID, DWORD, DWORD)),
            ( 'WinExec'         , (PVOID, DWORD)),
            ( 'CreateRemoteThread' , (HANDLE, PVOID, DWORD, PVOID, PVOID, DWORD, PVOID))
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
    'OpenProcess'            :True,
    'WriteProcessMemory'     :True,
    'WinExec'                :True,
    'CreateRemoteThread'     :True
}