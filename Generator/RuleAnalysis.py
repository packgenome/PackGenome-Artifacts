#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   SimilarityAnalysis.py
@Time    :   2021/12/24 21:12:05
@Author  :   Neko 
@Version :   1.0
@Contact :   
@License :   BSD
@Desc    :   None
'''

from functools import partial
from DataType import *
import re, sys, getopt, logging


def ruleConstruct(rulename, stringrule, condition):
    # generate yara rule
    rule = "rule {}\n{{\n".format(rulename)
    rule += "\tstrings:\n"
    rule += "\t\t{}\n".format(stringrule)
    rule += "\tcondition:\n"
    rule += "\t\t{}\n".format(condition)
    rule += "}\n"
    return rule

def conditionHandler(system="Windows", stringname = None, type = "all", counter = 0, partialFlag = False):
    if IS_X32ARCH:
        if system == "Windows":
            condition = "pe.is_32bit()" #"pe.machine==pe.MACHINE_I386"
        elif system == "LINUX":
            condition = "elf.machine==elf.EM_386"
        elif system == "ALL":
            condition = "((elf.machine==elf.EM_386) or (pe.machine==pe.MACHINE_I386))"
    else:
        if system == "Windows":
            condition = "pe.is_64bit()"#"pe.machine==pe.MACHINE_AMD64"
        elif system == "LINUX":
            condition = "elf.machine==elf.EM_X86_64"
        elif system == "ALL":
            condition = " ((elf.machine==elf.EM_X86_64) or (pe.machine==pe.MACHINE_AMD64))"
    
    # different methods to combine string rules
    if type == "all":
        condition += " and (any of them)"
    elif type == "combine":
        # tmp = ""
        # for name in stringname:
        #     tmp += "${} and ".format(name)
        # tmp = tmp[:-4]
        # condition += "({}) and ".format(tmp)
        if not partialFlag:
            if counter > 10:            
                counter = int(counter * 0.7)
                condition += " and ({} of them)".format(counter)
            else:
                condition += " and (all of them)"
        else:
            if counter <4:
                condition += " and (all of them)"
            else:
                counter = int(counter * 0.7)
                condition += " and ({} of them)".format(counter)


    # the base_of_code is not usable 
    # the overlay cause false negative when handling UPX programs
    if system == "Windows":
        # condition += ""
        # condition += """ and		(for any i in (0 .. pe.number_of_sections - 1): (
		# 	pe.sections[i].characteristics & pe.SECTION_CNT_CODE and
		# 	all in (pe.sections[i].raw_data_offset .. pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size)
		# ))"""
        condition += " and (pe.overlay.offset == 0 or for "+ str(int(counter * 0.7))+ " of ($*) : (@ < pe.overlay.offset))"
        condition += " and (not dotnet.is_dotnet)"
        #condition += "(for all of them : (pe.base_of_code <@ and @ < pe.base_of_code+pe.size_of_code))" #yara not good performance
    elif system == "LINUX":
        condition += ""
        pass # TODO YARA is not support find code section
        # condition += "(for any i in (1..elf.number_of_sections): ((elf.sections[i].flags & elf.SHF_EXECINSTR) and (for all of them : (elf.sections[i].offset <@ and @ < elf.sections[i].offset+elf.sections[i].size))))"
        # condition += "(for any i in (1..elf.number_of_segments): ((elf.segments[i].flags & elf.PF_X) and (for all of them : (elf.segments[i].offset <@ and @ < elf.segments[i].offset+elf.segments[i].file_size))))"

    return condition

def wildRuleHandler(bytesequence):
    # spile the sequence 
    rule = re.findall(r".{2}", bytesequence)
    rule = " ".join(rule)
    if WILD_LENGTH_MATCH in rule:
        #TODO support flexible scope
        rule.replace(WILD_LENGTH_MATCH, "[0-10]")
    return rule

def byteSelection(rule, counter, byteslist):
    # Bytes selection for rules
    avglen = 0
    # heuristic from experiment
    if counter!=0 and counter<2:
        for item in byteslist:
            avglen += item.count(" ") + 1
        
        avglen = int(avglen/counter)
        if avglen<6:
            return "rule nothing {}"
    else:
        return rule

def generateRule(packername, byteslist, INSlist, system="Windows", type="all", partialFlag = False):
    # TODO use different type to classify the priority of rules
    rulename = packername
    stringname = []
    stringlists = []
    stringrule = ""
    counter = 0

    for item, insn in zip(byteslist,INSlist):
        tmpname = "rule{}".format(counter)
        tmprule = item
        instructions = ""
        for ins in insn:
            instructions += "{}; ".format(ins) 

        stringname.append(tmpname)
        
        stringlists.append(tmprule)

        stringrule += "${0} = {{{1}}} \n\t\t// {2} \n\t\t".format(tmpname, tmprule, instructions)
    
        counter += 1


    condition = conditionHandler(system, stringname=stringname, type=type, counter=counter, partialFlag=partialFlag)
    rule = ruleConstruct(rulename, stringrule, condition)
    rule = byteSelection(rule, counter, byteslist)
    return rule