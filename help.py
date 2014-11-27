'''

@author: F4RR3LL
'''


# About
NAME        = "OpcodeAnalyzer"
VERSION        = "1.0"
AUTHOR        = "Author: PolymorphicCode"
INFO        = NAME+" v."+VERSION+"  \n"+AUTHOR+"\n"

# Help
def get():
    print INFO
    print
    print "Usage"
    print "".ljust(4), "./OpcodeAnalyzer.py -dir [PATH] -w [PATH] -dbg True"
    
    print
    print "Option"
    print "".ljust(4), "-dir".ljust(14), "Given path include files to opcode analyze"
    print
    print "".ljust(4), "-w".ljust(14), "Given directory to generate result on the directory with filename.extension.txt"
    print "".ljust(4), "-dbg".ljust(14), "Debug Option to see what is going on the program on monitor"
    print
    print "".ljust(4), "-help".ljust(14), "How to use opcode analyzer instructions"
    
