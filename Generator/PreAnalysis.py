#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   PreAnalysis.py
@Time    :   2021/12/24 21:12:05
@Author  :   Neko 
@Version :   1.0
@Contact :   
@License :   BSD
@Desc    :   None
'''

import json
from DataType import *
import angr
import sys, getopt, logging

l = logging.getLogger(name=__name__)

def GetInterestingSection(exename, CPA_mode=True):
    proj = angr.Project(exename)
    obj = proj.loader.main_object
    results = []
    for sec in obj.sections:
        #print(sec.name, sec.min_addr, sec.max_addr,sec.is_executable)
        if CPA_mode:
            if sec.is_executable: 
                results.append((sec.name, sec.min_addr, sec.max_addr, ORIGIN_CODE_TYPE))
            elif "idata" in sec.name:
                results.append((sec.name, sec.min_addr, sec.max_addr, ORIGIN_IAT_TYPE))
        elif (sec.size_of_raw_data==0 and sec.is_executable):
            results.append((sec.name, sec.min_addr, sec.max_addr, GUESS_ORIGIN_CODE_TYPE))
        elif sec.is_executable or ("data" not in sec.name and "rsrc" not in sec.name and "bss" not in sec.name): 
            results.append((sec.name, sec.min_addr, sec.max_addr, GUESS_CODE_TYPE))
        elif "idata" in sec.name:
            results.append((sec.name, sec.min_addr, sec.max_addr, GUESS_IAT_TYPE))
    return results

def outputFile(result, filename):
    with open(filename+'.prelog', 'w') as f:
        for i in result:
            f.writelines("{},{},{},{}\n".format(i[0].replace('\x00',''), i[1], i[2], i[3]))
            print("{},{},{},{}".format(i[0].replace('\x00',''), hex(i[1]), hex(i[2]), i[3]))

def usage():
    print("Usage: PreAnalysis.py [-f ExecutableFilePath -m WildMode]")

def main(argv):
    filename = ""
    mode = True

    try:
        opts, args = getopt.getopt(argv, "hf:m:")
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()

        elif opt == '-f':
            filename = arg
        elif opt == '-m':
            mode = False

        else:
            assert False, "unhandled option"

    if filename == "":
        usage()
        sys.exit(2)  

    exename = filename
    result = GetInterestingSection(filename,CPA_mode=mode)
    outputFile(result, filename.rstrip('.exe'))
    #print(result)

if __name__ == "__main__":
    main(sys.argv[1:])