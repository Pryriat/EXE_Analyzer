#coding:utf-8
import pefile
import da
import os
import sys

class pe:
    def __init__(self,pename):
        self.pe_info = pefile.PE(pename)
        self.pe_imports = {}#导入表
        self.size = float(os.stat(pename).st_size/1024)
        self.pe_name = os.path.basename(pename)
    def analyze(self):
        for x in self.pe_info.DIRECTORY_ENTRY_IMPORT:
            self.pe_imports[x.dll.decode("UTF-8")] = [y.name.decode("UTF-8") for y in x.imports if y.name is not None] 
        for x in self.pe_imports.keys():
            print x
            for y in self.pe_imports[x]:
                print y,
            print "======================================================"
    def tran_ana(self):
        for x in self.pe_info.DIRECTORY_ENTRY_IMPORT:
            self.pe_imports[x.dll.decode("UTF-8")] = [y.name.decode("UTF-8") for y in x.imports if y.name is not None]
        return self.pe_imports
