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

from dataclasses import replace
from functools import partial
import json
from DataType import *
import sys, getopt, logging
from RuleAnalysis import generateRule
average_exetimes = 0


md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
#TODO similar instruction combine the rules



def controlBytesHandler(binfo, minfo):
    #TODO check whether the jmp type is similar. if similar then replace the corresponding return
    #TODO intel XED
    sourcebytes = binfo.bytes[-binfo.controlsize*2:]
    matchedbytes = minfo.bytes[-minfo.controlsize*2:]
    # generate the control bytes rules
    bcontrol_bytes = ""
    mcontrol_bytes = ""
    for cb in CONTROL_BYTES:
        if "0f" in cb:
            if cb == sourcebytes[:4]:
                bcontrol_bytes = cb
            if cb == matchedbytes[:4]:
                mcontrol_bytes = cb 
        if cb == sourcebytes[:2]:
            bcontrol_bytes = cb
        if cb == matchedbytes[:2]:
            mcontrol_bytes = cb
        if bcontrol_bytes!="" and mcontrol_bytes!="":
            break
    if bcontrol_bytes==mcontrol_bytes:
        return " {}".format(bcontrol_bytes)
    else:
        return " ({}|{})".format(bcontrol_bytes, mcontrol_bytes)


def fullMatchedHandler(bytesinfo):
    binfo = bytesinfo
    minfo = binfo.matchedItem

    normalbytes = binfo.compbytes
    rule = re.findall(r".{2}", normalbytes)
    rule = " ".join(rule)



    rule += controlBytesHandler(binfo, minfo)
    return rule


def PartialMatched2Handler_BAKCUP(bytesinfo):
    binfo = bytesinfo
    minfo = binfo.matchedItem

    normalbytes = binfo.compbytes
    
    normalbytes = re.findall( r".{2}", normalbytes)
    print(normalbytes)
    for diffitem in binfo.diffbytesinfo:
        # different type 
        if diffitem[1]=="IMM":
            replacerange = diffitem[0]
            for index in range(replacerange[0], replacerange[1]):
                normalbytes[index] = "??"
        elif diffitem[1]=="REG":
            replacerange = diffitem[0]
            regbytes = normalbytes[replacerange[0]]
            regrule = "({}|{}|{}|{}|{}|{}|{}|{})"
            regs = []
            for i in range(8):
                regs.append( hex(((int(regbytes,16)>>3)<<3)^i)[2:] )
            regrule = regrule.format(*regs)
            print(regrule)
            normalbytes[replacerange[0]] = regrule
        elif diffitem[1]=="MEM_BASE":
            pass
        elif diffitem[1]=="MEM_INDEX":
            pass
        elif diffitem[1]=="MEM_DISP":
            # similar to JUMP
            pass
        elif diffitem[1]=="JUMP":
            replacerange = diffitem[0]
            wildnumber = replacerange[1]-replacerange[0]
            print(replacerange, len(normalbytes), diffitem)
            normalbytes = normalbytes[:replacerange[0]] + "[{}]".format(wildnumber) + normalbytes[replacerange[1]:]


    print(normalbytes)

    rule = " ".join(normalbytes)

    rule += controlBytesHandler(binfo, minfo)

    return rule

def PartialMatchedHandler(bytesinfo):
    binfo = bytesinfo
    minfo = binfo.matchedItem

    normalbytes = binfo.compbytes

    normalbytes = re.findall( r".{2}", normalbytes)

    poplist = []
    
    
    # avoid use too many special constructions
    # if bytesinfo.isPartialMatch2 and len(binfo.diffbytesinfo)>5:
    #     return ""


    for diffitem in binfo.diffbytesinfo:
        # different type 
        if diffitem[1]=="IMM":
            replacerange = diffitem[0]
            for index in range(replacerange[0], replacerange[1]):
                normalbytes[index] = "??"

        elif diffitem[1]=="REG":
            replacerange = diffitem[0]
            regbytes = normalbytes[replacerange[0]]
            regrule = "({}|{}|{}|{}|{}|{}|{}|{})"
            regs = []
            for i in range(8):
                regs.append( hex(((int(regbytes,16)>>3)<<3)^i)[2:] )
            regrule = regrule.format(*regs)
            # print(regrule)
            normalbytes[replacerange[0]] = regrule

        elif diffitem[1]=="MEM_BASE":
            pass
        elif diffitem[1]=="MEM_INDEX":
            pass
        elif diffitem[1]=="MEM_DISP":
            # similar to JUMP
            pass
        elif diffitem[1]=="JUNK_JUMP":
            replacerange = diffitem[0]

            # Situation1: junk instruction at the head of hexadecimal string
            # If the junk instructions at the head of strings, directly replace them to blank
            if replacerange[0] == 0:
                for index in range(replacerange[0], replacerange[1]):
                    normalbytes[index] = ""
                poplist.append(replacerange[2])
                continue

            # Situation2: junk instruction at the middle of hexadecimal sting
            else:
                wildnumber = replacerange[1]-replacerange[0]
                # print(replacerange, len(normalbytes), diffitem)
                for index in range(replacerange[0], replacerange[1]):
                    normalbytes[index] = ""
                poplist.append(replacerange[2])
                normalbytes[replacerange[0]] = "[0-{}]".format(wildnumber*2)

            # normalbytes = normalbytes[:replacerange[0]] + "[{}]".format(wildnumber) + normalbytes[replacerange[0]:]
        elif diffitem[1]=="JUMP":
            replacerange = diffitem[0]

            # Situation1: junk instruction at the head of hexadecimal string
            # If the junk instructions at the head of strings, directly replace them to blank
            if replacerange[0] == 0:
                for index in range(replacerange[0], replacerange[1]):
                    normalbytes[index] = ""
                continue
            else:
                if replacerange[1]>len(normalbytes):
                    normalbytes = []
                    continue
                wildnumber = replacerange[1]-replacerange[0]
                # print(replacerange, len(normalbytes), diffitem)
                for index in range(replacerange[0], replacerange[1]):
                    normalbytes[index] = ""
                normalbytes[replacerange[0]] = "[0-{}]".format(wildnumber*2)
            # normalbytes = normalbytes[:replacerange[0]] + "[{}]".format(wildnumber) + normalbytes[replacerange[1]:]
    # print("[generated_from_partial]", normalbytes)
    # print(normalbytes)

    # remove all the blank 
    normalbytes = list(filter(("").__ne__, normalbytes))
    bytecounter = 0

    insntmplist = []
    calcinscounter = 0
    
    for index, ins in enumerate(binfo.insn):
        if index not in poplist:
            insntmplist.append("{} {}".format(ins.mnemonic, ins.op_str))
            if ins.mnemonic!="mov" and ins.mnemonic!="lea":
                calcinscounter +=1

    if len(insntmplist)<2 or calcinscounter < 1:
        return ""
    
    bytesinfo.insn = insntmplist.copy()

    if len(normalbytes) > 2:
        for byte in normalbytes:
            if "[" not in byte and "?" not in byte:
                bytecounter += 1


        while True:
            if "[" in normalbytes[0]:
                normalbytes.pop(0)
            elif "]" in normalbytes[-1]:
                normalbytes.pop(-1)
            else:
                break
    else:
        return ""



    rule = " ".join(normalbytes)

    rule += controlBytesHandler(binfo, minfo)


    # print("[sourceins]", binfo.insn)
    # print("[dstins]", minfo.insn)
    # print("[diffbytesinfo]", binfo.diffbytesinfo)
    # print("[generated_from_partial]", rule)

    return rule


def findKernelBytes(fullmatched_list, partialmatched_list, rulename):
    byteslist = []
    byteslist_combined = []
    partial_byteslist = []
    partial2_byteslist = []
    INSlist = []
    INSlist_combined = []
    INSlist_partial = []
    INSlist_partial2 = []
    
    partialFlag = False

    for item in fullmatched_list:
        # Full match condition
        if item.isFullMatch and item.REN > 10**-3:# and item.exetimes > 1000:
            # try to generate full mathced rule
            tmprule = fullMatchedHandler(item)
            if tmprule!="" and tmprule not in byteslist:
                # singel instruction and jump instruction e.g. add eax,10; jmp 0x401000
                if item.insnum==2:
                    # byteslist_combined.append(item.bytes)
                    byteslist_combined.append(tmprule)
                    INSlist_combined.append(item.insn)
                else:
                    byteslist.append(tmprule)
                    INSlist.append(item.insn)

    for item in partialmatched_list:
        tmprule = PartialMatchedHandler(item)
        if item.isPartialMatch:
            if tmprule!="" and tmprule not in partial_byteslist:
                if item.insnum>2:
                    partial_byteslist.append(tmprule)
                    INSlist_partial.append(item.insn)
            pass
        elif item.isPartialMatch2:
            if tmprule!="" and tmprule not in partial_byteslist:
                if item.insnum>2:
                    partial2_byteslist.append(tmprule)
                    INSlist_partial2.append(item.insn)
            pass
            # tmprule = PartialMatchedHandler(item)
            pass

    # only when the other instruction is not enough, we need use the single+jump instruction
    if len(byteslist)<3:
    #TODO abnormal instruction can be combined e.g. scasb al, byte ptr es:[edi] jne 0x411058
        byteslist+=byteslist_combined
        INSlist += INSlist_combined
        if len(byteslist) < 10 and (len(partial_byteslist)>0 or len(partial2_byteslist)>0):
            byteslist += partial_byteslist
            INSlist += INSlist_partial
            byteslist += partial2_byteslist
            INSlist += INSlist_partial2
            partialFlag = True
    # TODO use the full list
    #generatedRule = generateRule("packername",byteslist)
    #generatedCombinedRule = generateRule("packername_combined",byteslist_combined,type="combine")

    generatedRule = generateRule(rulename+"_combined",byteslist, INSlist, type="combine", partialFlag=partialFlag)

    # print(generatedRule)

    return generatedRule


def markDifferentBytes(partialmatched_list):
    """
    Mark the different byte in the partial matched item
    """
    # TODO mark the difference bytes and type
    # TODO immediate difference
    # TODO register difference 
    # TODO memory difference
    if len(partialmatched_list)==0:
        return

    def differentInfoConstructor(base_offset, sourceins, dstins):
        """
        generate different bytes info
        @ diffinfo format [( startindex, endindex), "type"]
        """
        if len(sourceins.operands) == len(dstins.operands):
            # situation1: have similar operands
            for sop, dop in zip(sourceins.operands, dstins.operands):
                if sop.type == dop.type and sop.size == dop.size:
                    if sop.type == 1 and sourceins.reg_name(sop.value.reg)!=dstins.reg_name(dop.value.reg):
                        # different REG 
                        # print("[sourceinsn]",sourceinsn_list)
                        # print("[dstinsn]",dstinsn_list)
                        diffinfo = [ (base_offset+sourceins.modrm_offset, base_offset+sourceins.modrm_offset+ 1) , "REG"]
                        item.diffbytesinfo.append(diffinfo)
                        # print("[REG]", sourceins, dstins, sop.type, dop.type, sourceins.modrm_offset, dstins.modrm_offset)
                        break
                    elif sop.type == 2 and sop.value.imm!=dop.value.imm:
                        # different IMM
                        diffinfo = [ (base_offset+sourceins.imm_offset, base_offset+sourceins.imm_offset+ sourceins.imm_size) , "IMM"]
                        item.diffbytesinfo.append(diffinfo)
                        # print("[!]", sourceins.bytes, dstins.bytes, diffinfo, base_offset, sourceins.imm_offset, sourceins.imm_size)
                        # print("[IMM]", sourceins, dstins, sop.type, dop.type, sop.value.imm, dop.value.imm)
                    elif sop.type ==3:
                        # MEM
                        if sop.value.mem.base!=dop.value.mem.base:
                            pass
                        if sop.value.mem.index!=dop.value.mem.index:
                            pass
                        if sop.value.mem.disp!=dop.value.mem.disp:
                            dispoffset = min(sourceins.disp_offset,dstins.disp_offset)
                            maxdiffbyteslen = max(sourceins.disp_size,dstins.disp_size)
                            diffinfo = [ (base_offset+dispoffset, base_offset+dispoffset+maxdiffbyteslen), "JUMP"]
                            item.diffbytesinfo.append(diffinfo)
                            # print("[MEM_DISP]", sourceins, dstins, sop.type, dop.type, sop.mem.disp, dop.mem.disp, sourceins.disp_offset, sourceins.disp_size, dstins.disp_offset, dstins.disp_size)

                            pass
                    # break
                else:
                    # different type or different size
                    maxdiffbyteslen = max(len(sourceins.bytes.hex()), len(dstins.bytes.hex()))//2 - 1 # not count opcode
                    diffinfo = [ (base_offset, base_offset+maxdiffbyteslen), "JUMP"]
                    item.diffbytesinfo.append(diffinfo)
                    # print("[JUMP]", sourceins, dstins)
        else:
            # situation2: have different operands
            maxdiffbyteslen = max(len(sourceins.bytes.hex()), len(dstins.bytes.hex()))//2 - 1 # not count opcode
            diffinfo = [ (base_offset, base_offset+maxdiffbyteslen), "JUMP"]
            item.diffbytesinfo.append(diffinfo)
            # print("[JUMP]", sourceins, dstins)

    
    for item in partialmatched_list:
        binfo = item
        minfo = binfo.matchedItem
        bcompbytes = binfo.compbytes
        mcompbytes = minfo.compbytes
        # use base_offset to mark the start of difference
        base_offset = 0 

        # initialize the source and matched instruction list
        sourceinsn_list = []
        dstinsn_list = []

        for ins in md.disasm(bytes.fromhex(bcompbytes), 0):
            sourceinsn_list.append(ins)

        for ins in md.disasm(bytes.fromhex(mcompbytes), 0):
            dstinsn_list.append(ins)
        
        item.insn = sourceinsn_list
        item.matchedItem.insn = dstinsn_list

        if item.isPartialMatch:
            # have the same number of instructions with the same format 
            
            # print(sourceinsn_list)
            # print(dstinsn_list)
            for sourceins, dstins in zip(sourceinsn_list, dstinsn_list):
                # find the different bytes
                if sourceins.bytes!=dstins.bytes and sourceins.mnemonic == dstins.mnemonic:
                    # find the different syntactic
                    differentInfoConstructor(base_offset, sourceins, dstins)

                base_offset += len(sourceins.bytes.hex())//2

            

        elif item.isPartialMatch2:
            # may have junk instructions
            compareindex = 0
            source_base_index = 0

            for sourceindex, sourceins in enumerate(sourceinsn_list):
                # print(sourceins.mnemonic)
                comparecounter = 0

                if sourceins.mnemonic in GARBAGE_INS:
                    diffbyteslen = len(sourceins.bytes.hex())//2
                    diffinfo = [ (base_offset, base_offset+diffbyteslen, sourceindex), "JUNK_JUMP"] 
                    item.diffbytesinfo.append(diffinfo)
                    source_base_index=sourceindex

                    base_offset += len(sourceins.bytes.hex())//2
                    continue


                for dstindex, dstins in enumerate(dstinsn_list[compareindex:]):
                    # print(sourceins.mnemonic, dstins.mnemonic, len(sourceins.operands) == len(dstins.operands))
                    comparecounter += 1
                    # STEP1: locate junk instructions
                    if sourceins.mnemonic == dstins.mnemonic and len(sourceins.bytes) == len(dstins.bytes) and sourceins.opcode == dstins.opcode:
                        # STEP2: find the different bytes in similar instructions
                        compareFlag = False
                        for variable in item.slices.keys():
                            for instruction in item.slices[variable]:
                                if "{} {}".format(sourceins.mnemonic, sourceins.op_str) in instruction[0]:
                                    compareFlag = True
                        if compareFlag and dstindex-sourceindex<4:
                            differentInfoConstructor(base_offset, sourceins, dstins)
                            compareindex = dstindex
                            break
                            
                         # if index!=0:
                if comparecounter!=0 and comparecounter == len(dstinsn_list[compareindex:]):
                    # print(comparecounter, compareindex, len(dstinsn_list[compareindex:]), len(dstinsn_list))
                    diffbyteslen = len(sourceins.bytes.hex())//2
                    # check the existing diffinfo
                    # print("[sourceinsn]",sourceinsn_list)
                    # print("[dstinsn]",dstinsn_list)
                    # for diffinfo in item.diffbytesinfo:
                    #     if diffinfo[1]=="JUNK_JUMP" and diffinfo[0][0]< base_offset and base_offset > diffinfo[0][1] :
                    #         pass
                            # expand the existing jumo
                    
                    diffinfo = [ (base_offset, base_offset+diffbyteslen, sourceindex), "JUNK_JUMP"] 
                    # print(diffinfo)
                    item.diffbytesinfo.append(diffinfo)
                    

                base_offset += len(sourceins.bytes.hex())//2
                compareFlag = True

            # compareInsForm
            pass


def slicecompareInsns(sourcebytes, dstbytes):
    # TODO bug fix :  need check whether the slices lenght and instruction e.g. bytes_0x53d40a in test.vmp21381.log.json
    totallen = min(len(sourcebytes.insn), len(dstbytes.insn))
    simcount = 0
    falsecount = 0
    if sourcebytes.variable == dstbytes.variable:
        for var in sourcebytes.variable:
            if (sourcebytes.slices[var] == dstbytes.slices[var]):
                simcount += 1
            else:
                falsecount += 1

    totallen = simcount+falsecount
    # print(simcount, totallen)
    #TODO return other information including similarity rate
    if simcount!=0 and totallen!=0:
        return simcount/totallen
    else:
        return False


def totalCompareInsForm(sourcebs, dstbs):
    # compare the instruction form
    # example:
    #       mov reg, reg
    #       add reg, imm
    sourceinsn_list = []
    dstinsn_list = []

    for ins in md.disasm(bytes.fromhex(sourcebs.bytes), sourcebs.startaddr):
        sourceinsn_list.append(ins)

    for ins in md.disasm(bytes.fromhex(dstbs.bytes), dstbs.startaddr):
        dstinsn_list.append(ins)

    totallen = min(len(sourceinsn_list), len(dstinsn_list))-1 #not count the jmp instruction
    simcount = 0
    compareindex = 0

    if totallen==1:
        # not calculate single instruction
        return 0

    for sourceins in sourceinsn_list[:-1]:

        for index, dstins in enumerate(dstinsn_list[compareindex:-1]):
            if sourceins.mnemonic == dstins.mnemonic and len(sourceins.operands) == len(dstins.operands):
                opcounter = 0
                for sop, dop in zip(sourceins.operands, dstins.operands):
                    if sop.type == dop.type and sop.size == dop.size:
                        opcounter += 1
                if opcounter == len(sourceins.operands):
                    simcount+=1
                    compareindex = index
                    break

    # if simcount/totallen>0:
    #     print(sourcebs.insn, dstbs.insn, simcount, totallen, simcount/totallen)
    return simcount/totallen


def compareInsForm(sourceslice, dstslice):
    """
     input format : ["instruction string", "hexadecimal string"]

    # compare the instruction form
    # example:
    #       mov reg, reg
    #       add reg, imm
    """
    sourceinsn_list = sourceslice
    dstinsn_list = dstslice

    # for sourceinsn in sourceslice:
    #     for ins in md.disasm(bytes.fromhex(sourceinsn[1]), 0):
    #         sourceinsn_list.append(ins)

    # for dstinsn in dstslice:
    #     for ins in md.disasm(bytes.fromhex(dstinsn[1]), 0):
    #         dstinsn_list.append(ins)

    totallen = min(len(sourceinsn_list), len(dstinsn_list))
    simcount = 0
    compareindex = 0
    compareFlag = True

    for sourceins in sourceinsn_list:
        # SimIns
        # print(sourceins.mnemonic)
        for index, dstins in enumerate(dstinsn_list[compareindex:]):
            # print(sourceins.mnemonic, dstins.mnemonic, len(sourceins.operands) == len(dstins.operands))
            if compareFlag and sourceins.mnemonic == dstins.mnemonic and len(sourceins.operands) == len(dstins.operands):
                opcounter = 0
                for sop, dop in zip(sourceins.operands, dstins.operands):
                    if sop.type == dop.type and sop.size == dop.size:
                        opcounter += 1

                if opcounter == len(sourceins.operands):
                    # Match to this instruction; next comparasion start from this instruction.
                    simcount+=1
                    compareindex = index+1
                    compareFlag = False
        compareFlag = True

    # if simcount/totallen>0:
    #     print(sourcebs.insn, dstbs.insn, simcount, totallen, simcount/totallen)
    # print(sourceinsn_list, dstinsn_list, simcount, totallen, simcount/totallen)
    return simcount/totallen


def compareSlice(sourcebs, dstbytes):
    """
    Calculate the similarity of byteslist at slice level
    """
    totallen = max(len(sourcebs.slices.items()), len(dstbytes.slices.items()))
    if totallen < 2:
        return 0

    uselesscounter = 0
    totalcount = 0
    simcount = 0
    for sourcevar in sourcebs.variable:
        if sourcevar==None or "esp" in sourcevar:
            uselesscounter += 1
            continue

        # search the same variable
        if sourcevar in dstbytes.variable:
            # compare the instruction form
            # format : ["instruction string", "hexadecimal string"]
            if compareInsForm(sourcebs.slicesinsn[sourcevar], dstbytes.slicesinsn[sourcevar]) >0.9:
                simcount += 1
        totalcount += 1

    # not counting the esp related instructions
    if totalcount == 0:
        return 0

    totallen = totallen - uselesscounter
    # totalcount = totalcount/2
    # print(simcount, totallen)
    #TODO return other information including similarity rate
    # print(totallen, totalcount)
    simvalue = simcount/totallen
    if simvalue>0.3:
        l.debug("[!] Similarity info: {}, {}, {}, {}, {}, {}, {}".format(sourcebs.exetimes, dstbytes.exetimes, sourcebs.insn, dstbytes.insn, simcount, totalcount, simcount/totalcount))
    
    if simvalue==1:
        # check whether have the junk instructions
        if sourcebs.insnum==dstbytes.insnum:
            insSimCounter = 0
            for sourceins, dstins in zip(sourcebs.insn, dstbytes.insn):
                # compare the mnemonic of instruction
                if sourceins.split(' ', 1)[0] == dstins.split(' ', 1)[0]:
                    insSimCounter+=1
            if insSimCounter != sourcebs.insnum:
                simvalue=0.9
        else:
            simvalue=0.9


    return simvalue


def compareBytesList(sourcelist, dstlist):
    """
    Calculate the similarity of each ByteInfo item in sourcelist and dstlist
    """
    fullmatched_list = []
    partialmatched_list = []
    tmpdstlist = dstlist.copy()
    compareindex = 0
    compareFlag = True

    for sourcebs in sourcelist:
        compareFlag = True

        # for index, dstbs in enumerate(tmpdstlist[compareindex:]):
        for dstbs in tmpdstlist:
            # only find the first matched item
            if compareFlag:
                # avoid empty variable
                if len(sourcebs.variable)!=0:
                    # FULL match
                    if (sourcebs == dstbs) and sourcebs not in fullmatched_list:# or slicecompareInsns(sourcebs,dstbs)==1:
                        sourcebs.setMatchType("FULL", dstbs)
                        fullmatched_list.append(sourcebs)
                        tmpdstlist.remove(dstbs)
                        compareFlag = False
                        # compareindex = index
                        break

                    # partial match type 1
                    # elif sourcebs.insnum == dstbs.insnum and compareInsForm(sourcebs, dstbs)==1:
                    #     sourcebs.setMatchType("PARTIAL", dstbs)
                    #     partialmatched_list.append(sourcebs)
                    #     tmpdstlist.remove(dstbs)

                    #     # average_exetimes += sourcebs.exetimes

                    #     # compareindex = index
                        break
                    # partial match type 2
                    else:
                        # print(blockSim)
                        if sourcebs.insnum == dstbs.insnum  :
                            # print("PARTIAL", sourcebs, dstbs)
                            blockSim = compareSlice(sourcebs, dstbs)
                            if blockSim == 1:
                                sourcebs.setMatchType("PARTIAL", dstbs)
                                partialmatched_list.append(sourcebs)
                                tmpdstlist.remove(dstbs)
                                compareFlag = False
                                break

                        elif sourcebs.insnum>3 and dstbs.insnum>3 :
                            # print("PARTIAL2", sourcebs, dstbs)
                            blockSim = compareSlice(sourcebs, dstbs)
                            if blockSim > 0.8:
                                sourcebs.setMatchType("PARTIAL2", dstbs)
                                partialmatched_list.append(sourcebs)
                                tmpdstlist.remove(dstbs)
                                compareFlag = False
                                break

                        # break
            else:
                break

    return fullmatched_list, partialmatched_list

def tripleCompareFilter(cfull, cpartial, c1full, c1partial, c2full, c2partial):
    """
    Extract the common item from three different comparision result
    """
    fullmatched_list = []
    partialmatched_list = []

    # construct the common full list
    for citem in cfull:
        counter = 0
        for c1item in c1full:
            if citem==c1item:
                counter +=1
                break

        for c2item in c2full:
            if citem==c2item:
                counter += 1
                break

        if counter == 2:
            c1full.remove(c1item)
            c2full.remove(c2item)
            fullmatched_list.append(citem)
    
    # construct the common partial list
    # print(len(cpartial), len(c1partial), len(c2partial))
    for citem in cpartial:
        counter = 0
        for c1item in c1partial:
            if compareSlice(citem,c1item)>0.8:
                counter +=1
                break

        for c2item in c2partial:
            if compareSlice(citem,c2item)>0.8:
                counter += 1
                break

        if counter == 2:
            c1partial.remove(c1item)
            c2partial.remove(c2item)
            partialmatched_list.append(citem)   
    return  fullmatched_list, partialmatched_list


def cleanup():
    """
    Clean up the global variables
    """
    global FULLMATCHED_LIST
    global PARTIALMATCHED_LIST  
    FULLMATCHED_LIST = []
    PARTIALMATCHED_LIST = []

def json2type(filename):
    """
    Convert json to class BytesInfo 
    """
    result = []
    with open(filename, 'r') as f:
        fileBytes = json.load(f)
    for keys in fileBytes.keys():
        if "byte" in keys:
            tmp = fileBytes[keys]
            info = BytesInfo(tmp["start_addr"], tmp["end_addr"], tmp["called_time"], tmp["ins_num"])
            info.REN = tmp["REN"]
            info.insn = tmp["instructions"]
            info.variable = tmp["variable"]
            info.bytes = tmp["bytes"]
            info.slices = tmp["slices"]
            info.type = tmp["type"]
            info.controlsize = tmp["controlsize"]
            if info.controlsize==None:
                info.controlsize=0
            info.compbytes = info.bytes[:len(info.bytes)-info.controlsize*2]

            info.slicesinsn = info.slices.copy()

            # convert slice byte to insn
            for var in info.variable:
                if var!=None:
                    sourceinsn_list = []
                
                    for sourceinsn in info.slicesinsn[var]:
                        for ins in md.disasm(bytes.fromhex(sourceinsn[1]), 0):
                            sourceinsn_list.append(ins)
                    info.slicesinsn[var] = sourceinsn_list

            result.append(info)
    return result


def usage():
    print("Usage: SimilarityAnalysis.py [-s SourceJsonFilePath -t TargetJsonFilePath -f SecondTargetJsonFilePath]")


def main(argv):
    filename = ""
    tfile2 = ""

    try:
        opts, args = getopt.getopt(argv, "hs:t:f:")
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()

        elif opt == '-s':
            # source trace file path
            sfile = arg

        elif opt == '-t':
            # first target trace file path
            tfile = arg
        
        elif opt == '-f':
            # second target trace file path
            tfile2 = arg

        else:
            assert False, "unhandled option"

    if sfile == "" or tfile == "":
        usage()
        sys.exit(2)

    sresult = json2type(sfile)
    tresult = json2type(tfile)
    cfull, cpartial = compareBytesList(sresult, tresult)

    if tfile2!="":
        # compare three trace file mode
        t2result = json2type(tfile2)
        cleanup()
        c1full, c1partial = compareBytesList(sresult, t2result)
        cleanup()
        c2full, c2partial = compareBytesList(tresult, t2result)
        cleanup()
        fullmatched_list, partialmatched_list = tripleCompareFilter(cfull, cpartial, c1full, c1partial, c2full, c2partial)


    markDifferentBytes(partialmatched_list)
    print(findKernelBytes(fullmatched_list, partialmatched_list,"test"))
    # for i in cresult:
    #     print(i.exetimes, i.insn, i.bytes)



if __name__ == "__main__":
    main(sys.argv[1:])
