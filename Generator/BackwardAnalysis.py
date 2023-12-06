#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   traceFileOperation.py
@Time    :   2019/11/21 16:14:05
@Author  :   Neko

@Version :   1.0
@Contact :   
@License :   BSD
@Desc    :   None
'''

import json
import angr
from DataType import *
import logging
import re

l = logging.getLogger(name=__name__)

extractFilename = re.compile(".*\/(.*?)\.log")

class BackwardAnalysis(object):
    """
    """
    _INS_LIST = [] # Save instructions between the start and end of anchors
    _KERNEL_INS_LIST = [] # Save sliced instructions
    _sliced_list = {}
    _sliced_index = []
    _garbage_ins=["ret","test", "stc", "std", "cld", "clc", "cmp","cmc","call", "bt", "nop","emms","fnclex","wait","fninit"] # "cwde", "cwd", "rdtsc", "lahf", "cdq"
    _eax_dst_ins=["aaa", "aad", "aam", "aas", "rdtsc", "lahf", "cwde", "cbw", "mul", "div", "idiv"]  # special instructions whose destination is eax
    _edx_dst_ins=["cwd", "cdq"]  # special instructions whose destination is edx
    _simulation_expression = ""
    _simulation_result = False

    def __init__(self, insnList: Instruction, angrProj, obfuscator="VMProtect"):
        """
        """
        self.flush()
        self._insnList = insnList
        self.proj = angrProj
        self._obfuscator = obfuscator
        self._preProcess()
        self.valueSlicing()
    
    def _preProcess(self):
        """
        """
        index = 0
        for instruction in self._insnList:
            if instruction.mnemonic in self._garbage_ins or "j" in instruction.mnemonic:
                continue
            # l.debug(instruction)
            ins = Instruction(instruction, index, self.proj)
            index += 1
            self._INS_LIST.append(ins)

        # for backward slicing
        self._INS_LIST = self._INS_LIST[::-1]

        # if self._originalINS != None:
        #     self._originalINS = Instruction(self._originalINS, 0, self.proj, mulCPU=False, mode="fast")
            
        #     # special disposal of instructions with specific source and destination
        #     if self._originalINS.dst.flag=="MEM":
        #         # if "xadd" in self._originalINS.mnemonic or "xchg" in self._originalINS.mnemonic:
        #         #     self._dstRegister = self._originalINS.src
        #         #     self._secondOperand = self._originalINS.dst
        #         if self._originalINS.mnemonic in ["div", "idiv"] or (self._originalINS.mnemonic in ["mul", "imul"] and len(self._originalINS.operands)==1):
        #             self._dstRegister = Register("eax")
        #     else:
        #         if self._originalINS.mnemonic in self._eax_dst_ins or (self._originalINS.mnemonic=="imul" and len(self._originalINS.operands)==1):
        #             self._dstRegister = Register("eax")
        #         elif self._originalINS.mnemonic in self._edx_dst_ins:
        #             self._dstRegister = Register("edx")
        #         elif self._originalINS.dst.flag=="REG":
        #             self._dstRegister = self._originalINS.dst
                
        #         if self._originalINS.src:
        #             self._secondOperand = self._originalINS.src
    

        # for ins in self._INS_LIST:
        #     # rewrite xor REG, REG to mov REG, 0 (e.g., xor eax, eax to mov eax, 0)
        #     if ins.mnemonic=="xor" and ins.src==ins.dst and ins.src.flag=="REG":
        #             ins.rewrite("mov {}, 0".format(ins.src.realType),self.proj)
        #             continue
    
    def valueSlicing(self):
        valueList = []
        deadvalueList = []
        sliced_totalList = []
        
        ins_list = self._INS_LIST.copy()
        for ins in ins_list:
            if ins.dst not in valueList:
                valueList.append(ins.dst)
                #print(ins.dst.type)
        
        for value in valueList:
            if value in deadvalueList:
                continue

            self.backwardSlicing(ins_list ,value)

            if self._KERNEL_INS_LIST != []:
                self._sliced_list[value.type]= []#self._KERNEL_INS_LIST
                sliced_totalList += self._KERNEL_INS_LIST

                for ins in self._KERNEL_INS_LIST:
                    if ins.dst not in deadvalueList:
                        deadvalueList.append(ins.dst)
                    # remove junk instructions used by VMP2 and VMP3
                    self._sliced_list[value.type].append( ("{} {}".format(ins.insn.mnemonic, ins.insn.op_str), ins.insn.bytes.hex()) )
                    if ins in ins_list:
                        ins_list.remove(ins)
            
                self._KERNEL_INS_LIST = []

            for ins in sliced_totalList:
                self._sliced_index.append(ins.index)

    def backwardSlicing(self, ins_list, target, optimize=False):
        """
        """
        slice_operand = []
        for ins in ins_list:
            # if ins.mnemonic in ["cbw", "cwde"] and target == Register('eax'):
            #     self._KERNEL_INS_LIST.append(ins)
            if ins.dst == target:
                if ins.isDataTransfer():
                    # Data transfer Instructions
                    # "push", "pop", "pushfd", "popfd", "mov", "movzx",...
                    if ins.src.flag != "IMM" and (ins.isWriteMemory or ins.isReadMemory):
                        # not change target when meet not mov operation (e.g. add sub)
                        # e.g. (1) mov reg, [mem]/ mov [mem], reg ; (2) push reg/[mem]
                        target = ins.src

                    elif ins.src.flag == "IMM":
                        # Immediate value -> stop recording
                        # (1) mov reg/[mem], imm ; (2)push imm
                        target = ""

                    elif "mov" in ins.mnemonic:
                        if ins.src.flag == "REG" and ins.dst.flag == "REG":
                            # mov reg, reg
                            target = ins.src
                        # elif ins.src.flag == "IMM" and len(ins.operands)==2:
                        #     # mov reg/[mem], imm
                        #     # stop recording
                        #     target = ""
                
                elif ins.dst.flag == "REG" and ins.src.flag !="IMM" and len(ins.operands)==2:
                    # #if follow the add will lead to the push encrypt_key @VMProtect_2.x version
                    # <mnemonic> REG, REG/MEM
                    if "xchg" not in ins.mnemonic:
                        # add/sub/xxx reg, [mem]/reg
                        if ins.src not in slice_operand:
                            pass
                            # stop followning the CV obfuscation
                            # l.debug("[1]{} {} {} ".format(ins.index, ins.src.flag, ins.dst.flag))
                            slice_operand.append(ins.src)
                    else:
                        # xchg reg, reg/[mem];
                        target = ins.src
                        if ins.dst not in slice_operand:
                            slice_operand.append(ins.dst)

                elif ins.dst.flag == "MEM" and ins.src.flag =="REG" and len(ins.operands)==2:
                    # <mnemonic> MEM, REG
                    # add/sub/xxx [mem], reg
                    if self._obfuscator!="CV" and ins.src not in slice_operand:
                        l.debug("[2]{} {} {} ".format(ins.index, ins.src.flag, ins.dst.flag))
                        slice_operand.append(ins.src)

                elif "xchg" in ins.mnemonic:
                    # xchg reg/[mem], reg/[mem];
                    target = ins.src
                    if ins.dst not in slice_operand:
                        slice_operand.append(ins.dst)

                elif "div" in ins.mnemonic or "mul" in ins.mnemonic: 
                    # div, mul
                    # 不一定需要加上eax（看操作数），是否需要加上edx？
                    if self.proj.arch.name == "X86":
                        slice_operand.append(Register("eax"))
                    elif self.proj.arch.name == "AMD64":
                        slice_operand.append(Register("rax"))

                self._KERNEL_INS_LIST.append(ins)

            elif "div" in ins.mnemonic or "mul" in ins.mnemonic:
                if target!="" and self.proj.arch.name=="X86" and target.type=="eax":
                    # div, mul
                    slice_operand.append(target)
                    target=ins.src
                    # slice_operand.append(Register("eax"))
                    self._KERNEL_INS_LIST.append(ins)

            # Searching instructions related to new operand 
            for newop in slice_operand:
                if ins.dst == newop:
                    # l.debug(f"[backwardSlicing] {ins.index}, {ins.src.flag}, {ins.dst.flag}, {slice_operand}")
                    if ins in self._KERNEL_INS_LIST:
                        slice_operand.pop(slice_operand.index(newop))
                        break
                    self._KERNEL_INS_LIST.append(ins)

                    if ins.isDataTransfer():
                        # Data transfer
                        # "push", "pop", "pushfd", "popfd", "mov", "movzx",...
                        if ins.src.flag != "IMM" and (ins.isWriteMemory or ins.isReadMemory):
                            # Data transfer e.g. mov reg, [mem]/ mov [mem], reg ; push reg/[mem]
                            slice_operand[slice_operand.index(newop)]=ins.src
                        elif ins.src.flag == "IMM":
                            # (1) mov reg/[mem], imm ; (2)push imm
                            # stop recording
                            slice_operand.pop(slice_operand.index(newop))
                        elif "mov" in ins.mnemonic:
                            if ins.dst.flag == "REG" and ins.src.flag == "REG":
                                # mov reg, reg
                                slice_operand[slice_operand.index(newop)] = ins.src
                            # elif ins.src.flag == "IMM" and len(ins.operands)==2:
                            #     # mov reg/mem, imm
                            #     slice_operand.pop(slice_operand.index(newop))

                    elif ins.dst.flag == "REG" and ins.src.flag !="IMM" and len(ins.operands)==2:
                        # if ins.isDataTransfer():
                        #     # mov reg, reg
                        #     slice_operand[slice_operand.index(newop)]=(ins.src)
                        if "xchg" not in ins.mnemonic:
                            # add/sub/xxx reg, [mem])
                            if self._obfuscator!="CV" and ins.src not in slice_operand:
                                slice_operand.append(ins.src)
                            else:
                                continue
                        else:
                            slice_operand[slice_operand.index(newop)]=ins.src

                    elif "xchg" in ins.mnemonic:
                        # xchg reg/[mem], reg/[mem]
                        slice_operand[slice_operand.index(newop)]=ins.src

                elif type(ins.dst) == list and newop in ins.dst:
                    if "div" in ins.mnemonic or "mul" in ins.mnemonic:
                        l.warning("Abnormal instruction: {}: {} {} {}", ins.index, ins.address, ins.mnemonic, ins.op_str)
                        # slice_operand.pop(slice_operand.index(newop))
                        # slice_operand += ins.src
                        # self._KERNEL_INS_LIST.append(ins)

    @property
    def slicedList(self):
        return self._sliced_list.copy()

    def flush(self):
        """
        """
        self._INS_LIST = []
        self._KERNEL_INS_LIST = []
        self._sliced_list = {}

    def printSlices(self, status=True):
        """
        Simple print
        """
        for ins in self._KERNEL_INS_LIST[::-1]:
            if status:
                print(f"{ins.index}: {hex(ins.address)}, {ins.mnemonic} {ins.op_str}; READ={hex(ins.raddr)}, WRITE={hex(ins.waddr)}, ESP={hex(ins.regs.esp)}")
            else:
                print("{}: {}, {} {}; EAX={}, EBX={}, ECX={}, EDX={}, ESI={}, EDI={}, ESP={}, EBP={}, EFLAGS={}, READ={}, WRITE={}, CONCRET={}".format(ins.index,hex(ins.address), ins.mnemonic,ins.op_str,*[hex(ins.regs.registers[j]) for j in ins.regs.registers.keys()],hex(ins.raddr),hex(ins.waddr),ins.concrete))

    def exportHandlerSlices(self, flag=False):
        """
        Export instructions with handler mark
        """
        address = []
        for handler in self._handlers:
            for ins in handler.ins_list:
                if ins.mnemonic in self._garbage_ins:
                    continue
                elif ins.mnemonic[0] == "j" and ins.dst.flag!="REG":
                    continue

                address.append(hex(ins.address))
                # print(f"{i.index}: {hex(i.address)}, {i.mnemonic} {i.op_str}; READ={hex(i.raddr)}, WRITE={hex(i.waddr)}, ESP={hex(i.regs.esp)}")
                print("{}: {}, {} {}; EAX={}, EBX={}, ECX={}, EDX={}, ESI={}, EDI={}, ESP={}, EBP={}, EFLAGS={}, READ={}, WRITE={}".format(ins.index,hex(ins.address), ins.mnemonic,ins.op_str,*[hex(ins.regs.registers[j]) for j in ins.regs.registers.keys()],hex(ins.raddr),hex(ins.waddr)))
            print("="*30)

        if flag==True:
            address_dict = {}
            for ins_addr in set(address):
                address_dict[ins_addr]=address.count(ins_addr)
            print(sorted(address_dict.items(), key= lambda kv:(kv[1], kv[0])))

    def printSlicesToFile(self, path: str, select: str):
        """
        Print instruction list to text file
        """
        if select == "kernel":
            with open(path + "/" + self._filename + ".kernel.txt",'w') as f:
                tmp = self._KERNEL_INS_LIST[::-1]
                for ins in tmp:
                    f.writelines("{}: {}, {} {}; EAX={}, EBX={}, ECX={}, EDX={}, ESI={}, EDI={}, ESP={}, EBP={}, EFLAGS={}, READ={}, WRITE={}, CONCRET={}\n".format(ins.index,hex(ins.address), ins.mnemonic,ins.op_str,*[hex(ins.regs.registers[j]) for j in ins.regs.registers.keys()],hex(ins.raddr),hex(ins.waddr),ins.concrete))
                        
        elif select == "full":
            with open(path + "/" + self._filename + ".full.txt",'w') as f:
                tmp = self._INS_LIST[::-1]
                for ins in tmp:
                    f.writelines("{}: {}, {} {}; EAX={}, EBX={}, ECX={}, EDX={}, ESI={}, EDI={}, ESP={}, EBP={}, EFLAGS={}, READ={}, WRITE={}, CONCRET={}\n".format(ins.index,hex(ins.address), ins.mnemonic,ins.op_str,*[hex(ins.regs.registers[j]) for j in ins.regs.registers.keys()],hex(ins.raddr),hex(ins.waddr),ins.concrete))

    
    def outputToFile(self, storeDir: str, less=False):
        """
        Print instruction list to json file for further analysis
        """
        if not storeDir.endswith("/"):
            storeDir += "/"
        f = open(storeDir + self._filename + ".json", "w")
        
        kernel_list = []
        for ins in self._KERNEL_INS_LIST[::-1]:
            kernel_list.append([ins.index, hex(ins.address), ins.mnemonic, ins.op_str])
        
        full_list = []
        if not less:
            for ins in self._INS_LIST[::-1]:
                full_list.append([ins.index, hex(ins.address), ins.mnemonic, ins.op_str])
        
        data = {"filename":self._filename, "ins":self._originalINS_str, "kernel_list":kernel_list, "full_list":full_list, "simulation":[str(self._simulation_expression), self._simulation_result]}
        f.write(json.dumps(data))
        f.close()    
    

if __name__ == "__main__":

    l.setLevel(20)
    originalINS = "xor ebx, 0xdead"
    originalRegister=Register("ebx")
    # originalRegister=Memory(0x69fe94,0x69fe94)
    test = TraceAnalysis(traceFileName="instrace.txt", programFileName="VMnew_cmpxchg64.vmp.exe", anchor="fadd st(7)", originalINS=originalINS, originalRegister=originalRegister, obfuscator="VMProtect")
    # test = TraceAnalysis("instrace.txt", "VMnew_nop.vmp.exe", "cmpxchg eax, eax", None, originalRegister)
    # test = TraceAnalysis("instrace.txt", "CVfish.exe", "cmpxchg eax, eax", None, originalRegister, obfuscator="CV")

    # test = TraceAnalysis(traceFileName="{}.txt".format(contextname), programFileName="{}.vmp.exe".format(contextname), anchor="fadd st(7)", originalINS=None, originalRegister=originalRegister, obfuscator="VMProtect")

    # print(test.searchAnchor())

    # test.searchContextSwitch(mode="standard")

    # test.isReadBytecode()

    test.backwardSlicing(originalRegister)
    print("\n")
    print(test.inputRecoginition())
    test.printSlices(False)

    test.dataflow()
    test.printSlices(False)
    test.symbolicExecution()

    # print(test._KERNEL_INS_LIST[0].regs_read,test._KERNEL_INS_LIST[0].regs_write)

    # for i in test._INS_LIST[::-1]:
        # if i.mnemonic=="pushfd" or i.mnemonic=="popfd":
            # print(i.regs_read, i.regs_write,i.reg_name(25), i.src, i.dst, i.waddr, i.raddr)
        # if "push" in i.mnemonic or "pop" in i.mnemonic:
        # print(i.index, hex(i.address), i.mnemonic, i.op_str, hex(i.waddr), hex(i.raddr), hex(i.regs.esp))
    # print(ConcretRegister.registers.keys())
