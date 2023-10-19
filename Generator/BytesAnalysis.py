#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   BytesAnalysis.py
@Time    :   2021/12/24 21:12:05
@Author  :   Neko 
@Version :   1.0
@Contact :   
@License :   BSD
@Desc    :   None
'''

import json
import os
from DataType import *
from BackwardAnalysis import BackwardAnalysis
import angr
import sys, getopt, logging

l = logging.getLogger(name=__name__)

interesting_bslist = []
total_exetimes = 0

def filterItems(bslist):
    global total_exetimes

    interbs = interesting_bslist
    if len(interbs)>0:
        while True: 
            counter = 0
            newlist = []
            for item in bslist:                
                if item not in interbs:
                    for target in interbs:
                        # frequency is similar
                        # target.exetimes > total_exetimes
                        # if item.exetimes > target.exetimes/10:
                            # control flow analysis
                            if item.startaddr in target.nextbb or target.startaddr in item.nextbb:
                                # propagate labels
                                item.type = target.type
                                newlist.append(item)
                                counter += 1
                                l.debug("{} {} {} {}".format(item.address,target.address, item.exetimes, target.exetimes))
            interbs += newlist
            if counter == 0:
                break

    for item in bslist:
        # calculate total execution time
        if item.type!=""and item.isStatic:
            total_exetimes += item.exetimes

    for item in bslist:
        item.REN = item.exetimes/total_exetimes

    return bslist

def FindStaticBytes(exename, bslist):
    # result = []
    proj = angr.Project(exename)
    
    if proj.arch.name == "AMD64":
        setArch(False)
    for item in bslist:
        try:
            compare = proj.loader.memory.load(item.startaddr, item.bytelen).hex()
        except:
            l.warning("[!] Out of Binary address: {} {}".format(hex(item.startaddr), item.bytelen))
            continue
        # print(compare, item.bytes, compare==item.bytes)
        if (compare!=item.bytes or item.bytelen==0):
            continue
        
        # size=item.bytelen - fix angr's bugs that cannot recognize some basic blocks
        bbl = proj.factory.block(item.startaddr, size=item.bytelen)
        tmpinsn = bbl.capstone.insns
        # print(item.bytelen, item.bytes, bbl.capstone.insns)

        # rep movsb and related instructions is not in the same block 
        if bbl.instructions > 0 and "rep" in tmpinsn[-1].insn.mnemonic:
            repnextbbl = proj.factory.block(item.startaddr+bbl.size)
            item.insn = tmpinsn + repnextbbl.capstone.insns

            if len(repnextbbl.vex.constant_jump_targets) != 0:
                if len(repnextbbl.vex.constant_jump_targets)>1:
                    # avoid add wrong address Ijk_MapFail
                    for targets in repnextbbl.vex.constant_jump_targets_and_jumpkinds.keys():
                        if repnextbbl.vex.constant_jump_targets_and_jumpkinds[targets] != 'Ijk_MapFail':
                            item.nextbb.append(targets)
                else:
                    item.nextbb = list(repnextbbl.vex.constant_jump_targets)

        else:

            if bbl.instructions==item.insnum:
                item.insn = bbl.capstone.insns
            else:
                """
                Many packers trigger exception for jumping to other instructions.
                e.g. armadillo will use "pop dword ptr [eax]" (eax=0) 
                To avoid generate a bigger basic block, need to only record the current instructions.
                """
                item.insn = bbl.capstone.insns[:item.insnum]
            
            # item.bytes = bbl.bytes.hex()
            # basic block jump address
            """
                Construct control flow information
            """
            if len(bbl.vex.constant_jump_targets) != 0:
                if len(bbl.vex.constant_jump_targets)>1:
                    # avoid add wrong address Ijk_MapFail
                    for targets in bbl.vex.constant_jump_targets_and_jumpkinds.keys():
                        if bbl.vex.constant_jump_targets_and_jumpkinds[targets] != 'Ijk_MapFail':
                            item.nextbb.append(targets)
                else:
                    item.nextbb = list(bbl.vex.constant_jump_targets)

            else:
                # fix angr's bugs that cannot recognize some basic blocks
                tmpinsn = bbl.capstone.insns[-1].insn
                if hex(tmpinsn.opcode[0])[2:] in CONTROL_BYTES and tmpinsn.opcode[0] != 0xc3 and "ptr" not in tmpinsn.op_str and "0x" in tmpinsn.op_str:
                    targets = int(tmpinsn.op_str,16)
                    item.nextbb.append(targets)
    
        item.splitedinsn = BackwardAnalysis(item.insn, proj).slicedList
        
        if len(item.insn) > 0:
            item.controlsize = item.insn[-1].size

        # total_exetimes += item.exetimes
        #print(item.splitedinsn)
        item.isStatic = True
        # result.append(item)

        # appending interesting items
        # ORIGIN_CODE_TYPE -> original .text section
        # GUESS_ORIGIN_CODE_TYPE -> guess original .text section
        # EXEMEM_TYPE -> writeable and executable memory
        # TODO use any labels
        if (ORIGIN_CODE_TYPE in item.type) or \
            (GUESS_ORIGIN_CODE_TYPE in item.type) or \
            (EXEMEM_TYPE in item.type): 
            interesting_bslist.append(item)

    return bslist


def logFormating(filename):
    result = []
    with open(filename, 'r') as f:
        for line in f:
            result.append(ByteSequence(line))
    return result

def byteSortFile(bslist, filename, outjson=False, output_dir="./"):
    result = sorted(bslist, reverse=True)
    print("The number of selected bytes: {}".format(len(bslist)))
    with open(os.path.join(output_dir, filename+'.sorted'), 'w') as f:
        for item in result:
            f.write("{}, {}, {}, {}, {}\n".format(item.address, item.exetimes, item.insnum, item.bytes, item.type))
    if outjson:
        outputJson(result, filename, output_dir)

def outputJson(bslist, filename, output_dir):
    outjson = {
        "FileName": filename,
        "Obfuscator": "??",
        "Version" : "??"
    }
    for item in bslist:
        # control the output type
        if item.type!="" and item.isStatic and item.insnum!=1:
            outjson["bytes_{}".format(hex(item.startaddr))]={
                "start_addr": hex(item.startaddr),
                "end_addr": hex(item.endaddr),
                "called_time": item.exetimes,
                "REN" : item.REN,
                "type":item.type,
                "nextbb":item.nextbb,
                "ins_num": item.insnum,
                "bytes": item.bytes,
                "controlsize":item.controlsize,
                "instructions": ["{} {}".format(ins.mnemonic, ins.op_str) for ins in item.insn],
                "variable": list(item.splitedinsn.keys()),
                "slices": item.splitedinsn
            }
    with open(os.path.join(output_dir, filename+'.json'), 'w') as f:
        json.dump(outjson, f, indent=4)
            
# output json format
"""
{
    "FileName": "xxx.exe"
    "Obfuscator" : "??",
    "Version" : "",
    "bytes_0x4???": {
        "start_addr" : 0x???,
        "end_addr" : 0x???,
        "called_time" : ?,
        "ins_num" : ?,
        "bytes" : "fffffff",
        "variable" : ['ebx', 'ecx'],
        "slices" : {
            'ebx': ["mov ebx, xxx", "..."], 
            'ecx': ["add ecx, xxx", "..."]},
            ...
            }
        }
}
"""


def usage():
    print("Usage: BytesAnalysis.py [-f LogFilePath]")


def main(argv):
    filename = ""

    try:
        opts, args = getopt.getopt(argv, "hf:")
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()

        elif opt == '-f':
            # trace file path
            filename = arg
        else:
            assert False, "unhandled option"

    if filename == "":
        usage()
        sys.exit(2)  
    exename = os.path.splitext(filename)[0] + ".exe"
    result = logFormating(filename)
    result = FindStaticBytes(exename, result)
    result = filterItems(result)
    byteSortFile(result, filename, outjson=True)

if __name__ == "__main__":
    main(sys.argv[1:])