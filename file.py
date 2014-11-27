'''


@author: F4RR3LL
'''


#!/usr/bin/python


"""
    Analyzed File 
     include File name ,Opcode , OpCode Format Display ,OpCode Size , All OpCode Size
     Created By PolymorphicCode 2014 GIT

"""

import sys
import os.path
import json

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from mimetypes import MimeTypes
import urllib


class AnalyzedFile:
    
     def __init__(self):
       self.opCodeDic = dict() #  opcodes stored with percentages
       self.opCodeList = []  # general PEL file includes all opcodes
       self.opCodesFormatted = [] # formatted mnemonic,address,op_str for debug
       self._filename = ''
       self._filePath = ''
       self.fileType = '' #extension of file
     
     
     def addopCode(self,opcode):
         self.opCodeList.append(opcode)
         
         
         
     def addopcodeFormatted(self,opcodeformattedString):
         self.opCodesFormatted.append(opcodeformattedString)
             
     
     def setanalyzedFileName(self,name):
         self._filename = os.path.basename(name)
         
         
         

     def setanalyzedFileType(self,path):
           mime = MimeTypes()
           url = urllib.pathname2url(path)
           mime_type = mime.guess_type(url)
           self.fileType = mime_type  
         
         
     def setanalyzedFilePath(self,path):
         self._filePath = path
         
         
     
     def getFileName(self):
         return self._filename
     
     
     def getfilePath(self):
         return self._filePath
         
     def getallOpCodes(self):
         return self.opCodeList    
     
     def getopPercentages(self):
         return self.opCodeDic
     
     def getformattedOpcodes(self):
         return self.opCodesFormatted
     
     def getallOpcodesize(self):
         return len(self.opCodeList)
     
     def getopCodeSize(self):
         return len(self.opCodeDic)
    
     
     # return file type
     def getFileType(self):
         return self.fileType              
            
      # calculate OpcodeList percentage of each opCode from file
     def __calculatePercentagesOpCode__(self):
            
            if len(self.opCodeList) != 0:        
                for i in self.opCodeList:
                    state = self.opCodeDic.get(i)
                    if state is None:
                      counter = 0
                      for k in self.opCodeList:
                        if i == k:
                            counter = counter + 1                   
                      self.opCodeDic[i] = round((counter / float(len(self.opCodeList))) * 100.0,2)     
                return self.opCodeDic
              
   
   
   # print diassembled binary data formatted
     def __showDiassebledCode__(self):
            for i in self.opCodesFormatted:
                print i
                
                
     def toString(self):
         
         fileinfo = {}
         #fileinfo['Opcode Percent'] = str(json.dumps(self.opCodeDic, sort_keys=True,indent = 4 ,separators=(',',':')))
         fileinfo['FileName'] = str(self._filename)  
         fileinfo['Total Opcode Size'] = str(self.getallOpcodesize())
         fileinfo['Set(Opcode Size)'] = str(self.getopCodeSize())
         fileinfo['File Type'] = str(self.fileType)
        
         return fileinfo,self.opCodeDic
                
                
                
                
                
                
                
                
                
                
                    
