'''


@author: F4RR3LL
'''


#!/usr/bin/python

import sys
import os.path
import opcode


sys.path.append(os.path.join(os.path.dirname(__file__), '..'))


try:
from capstone import *
except ImportError:
print 'import capstone module failed'
exit(0)



import argparse
import binascii
import fnmatch
import os
from os.path import isfile
from file import AnalyzedFile
import json
import help
import ConfigParser



"""
    OpCode Analyzer 
    
    
    Run Options : 
    
         -dir  [PATH]  directory include single or more file to diassemble
         -dbg [True]  Debug Mode display Opcodes diassembled from given file
         -db database connections next version
         -w [PATH]  results stored into given path
         
 Usage : python OpCodeAnalyzer.py -dir [PATH] -w [PATH] -dbg True ( display on the screen )

    Created By PolymorphicCode 2014 
"""


class OpcodeAnalyzer:
    def __init__(self):

       self.files = []   # read from directory files stored
       self.AnalyzedFileObjects = [] # analyzed file object lists 
       self.executedFilename=''
       self.executedFilePath=''
       
    # Read file as hex
    def __readFileAsHex__(self,filename):
        #read exe file then display hex and opcode
        self.executedFilePath = filename
        try:
         f = open(filename,'rb')
        except IOError:
            raise Exception( "Error: can\'t find file or read data %s" % filename)
       
        content = f.read()
        data =  binascii.hexlify(content)
        d = binascii.unhexlify(data)
        #data =  binascii.hexlify(content) 
        f.close()
        return content


# Read given directory path and store all files in directory  
# No control type of file   
    def __readDir__(self,dirname):
        if os.path.isdir(dirname):
         for file in os.listdir(dirname):
            #if fnmatch.fnmatch(file, '*.exe'):
              self.executedFilename = file
              url = dirname + '\\' + file
              self.files.append(url) 
         
    
                
    # diassembler function 
    # diassemble given binary data to opcodes
    def  __generateOpCodeFromHex__(self,data):
            try:
                analyzedFile = AnalyzedFile()
                md = Cs(CS_ARCH_X86, CS_MODE_16)
                ##'\x55\x48\x8b\x05\xb8\x13\x00\x00'  55 48 8b
                for i in md.disasm(data, 0x1000):
                    
                    analyzedFile.addopCode(i.mnemonic)
                    str = "0x{}: \t{}\t\t{}" .format(i.address, i.mnemonic, i.op_str)
                    analyzedFile.addopcodeFormatted(str)
                    
                return analyzedFile    
            except CsError as e:
                print("ERROR: %s" %e)
    
             
    # diassemble and calculate percentage of each file given directory path            
    def __run__(self):
        
        for i in self.files:
            try:
                data = self.__readFileAsHex__(i)
                analyzedFile = self.__generateOpCodeFromHex__(data)
                analyzedFile.setanalyzedFileName(i) # this take filename from path
                analyzedFile.setanalyzedFilePath(i) # path include
                analyzedFile.setanalyzedFileType(i) # set mime-type of file
                
                #self.__showDiassebledCode__()
                # self.__calculatePercentagesOpCode__()
                self.AnalyzedFileObjects.append(analyzedFile) # add analyzed file to list
                
            except Exception as e:
                print "{} ".format(e)
                
          


def formatted(dictionary):
    return  json.dumps(dictionary, sort_keys=True,indent = 4 ,separators=(',',':'))
                     
                
if __name__ == "__main__":
        
        
     
    parser = argparse.ArgumentParser(description='OpCode Analyzer Tool version 1.0')
    
    parser.add_argument('-dir',help='Directory Path',required=True)
    parser.add_argument('-w',help='Result stored in given path',required=False)
    parser.add_argument('-dbg',help='Debug Mode display generated Opcodes and instructions',required=False)
    parser.add_argument('-help',help = 'How to use opcode analyzer instructions ',required = False)
    parser.add_argument('-version',help = 'Version',required =False)
    args = vars(parser.parse_args())
    
    
   

    
 
    
    if args['help'] is not None:
            print help.get()
            exit(0)
            
    if args['version'] is not None:
         print help.VERSION
         exit(0)        
    
    if args['dir'] is not None:  
        op = OpcodeAnalyzer()
        op.__readDir__(args['dir'])
        op.__run__()
        for i in op.AnalyzedFileObjects:
               i.__calculatePercentagesOpCode__()  # calculate OpCode percentage
             
        
        
          
    if args['w'] is not None:
            for i in op.AnalyzedFileObjects: # analyzedefileobject include file type and others
                file = open(args['w']+'\\'+i.getFileName()+'.txt','w')
                
                fileinfo,opcodeDic = i.toString()
                parser = ConfigParser.SafeConfigParser()
                parser.add_section('File Information')
                for key,value in fileinfo.iteritems():
                    parser.set('File Information',key,value)
                
                
                parser.set('File Information','Opcode Percent',
                           json.dumps(formatted(opcodeDic), sort_keys=True,indent = 4 ,separators=(',',':')))    
                parser.write(file)    
                                
                
                
            
            
    if  args['dbg'] is not None and args['dbg'] == 'True':
        for i in op.AnalyzedFileObjects:
           fileinfo ,opcodeDic =  i.toString()
           print "File Information\n"
           print formatted(fileinfo)
           print "\n Opcode Percent \n"
           print formatted(opcodeDic)
           
             
    
