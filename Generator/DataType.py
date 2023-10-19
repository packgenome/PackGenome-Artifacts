#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   DataType.py
@Time    :   2021/12/23 19:56:20
@Author  :   Neko
@Version :   1.0
@Contact :
@License :   BSD
@Desc    :   None
'''

import logging
import re
from capstone import *

l = logging.getLogger(name=__name__)

EAX_LIST = ["rax", "eax", "ax", "al", "ah"]
EBX_LIST = ["rbx", "ebx", "bx", "bl", "bh"]
ECX_LIST = ["rcx", "ecx", "cx", "cl", "ch"]
EDX_LIST = ["rdx", "edx", "dx", "dl", "dh"]
EBP_LIST = ["rbp", "ebp", "bp"]
ESI_LIST = ["rsi", "esi", "si", "sil","sih"]
EDI_LIST = ["rdi", "edi", "di","dil","dih"]
ESP_LIST = ["rsp", "esp", "sp"]

REG64_LIST = ["rax", "rbx", "rcx", "rdx", "rbp", "rsi", "rdi", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
REG32_LIST = ["eax", "ebx", "ecx", "edx", "ebp", "esi", "edi", "esp"]
REG16_LIST = ["ax", "bx", "cx", "dx", "bp", "si", "di", "sp"]
REG8_LIST = ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"]


CONTROL_BYTES = ["c3","9a","e8","ff","eb","e9","ea","77","73","72","76","e3","74","7f","7d","7c","7e","75","71","7b","79","70","7a","78","0f87","0f83","0f82","0f86","0f84","0f8f","0f8d","0f8c","0f8e","0f85","0f81","0f8b","0f89","0f80","0f8a","0f88"]
GARBAGE_INS=["pushfd", "pushal","ret","test", "stc", "std", "cld", "clc", "cmp","cmc","call", "bt", "nop","emms","fnclex","wait","fninit"] # "cwde", "cwd", "rdtsc", "lahf", "cdq"

IS_X32ARCH= True

ORIGIN_CODE_TYPE = 'a'
ORIGIN_IAT_TYPE = 'b'
GUESS_ORIGIN_CODE_TYPE = 'c'
GUESS_CODE_TYPE = 'd'
GUESS_IAT_TYPE = 'e'
EXEMEM_TYPE = 'm'

WILD_LENGTH_MATCH = '@@'

def setArch(arch):
    global IS_X32ARCH 
    IS_X32ARCH = arch

class ByteSequence():

    def __init__(self, infoline):
        self.address, self.exetimes, self.insnum, self.bytes, self.type, other = infoline.split(',')
        # self.bytes = self.bytes[:-1]
        self.exetimes = int(self.exetimes)
        self.REN = None
        self.isStatic = False
        self.insnum = int(self.insnum)

        self.startaddr, self.endaddr = self.address.split('-')
        self.startaddr = int(self.startaddr, 16)
        self.endaddr = int(self.endaddr, 16)

        self.bytelen = len(self.bytes)//2
        self.insn = None

        self.splitedinsn = None

        self.nextbb = []
        self.controlsize = None

    def __lt__(self, other):
        return (self.exetimes < other.exetimes)

    def __eq__(self, other):
        return (self.bytes == other.bytes)

    def __gt__(self, other):
        return (self.exetimes > other.exetimes)

class BytesInfo():

    def __init__(self, start_addr, end_addr, exetimes, insnum):

        self.startaddr = int(start_addr, 16)
        self.endaddr = int(end_addr, 16)
        
        self.exetimes = int(exetimes)
        self.REN = None

        self.insnum = int(insnum)

        self.insn = None
        self.bytes = None
        self.variable = []
        self.slices = {}

        self.type = None
        self.controlsize = None
        self.compbytes = None

        self.matchtype = "NOMATCH"
        self.matchedItem = None

        self.diffbytesinfo = []
        # [ [ range, "different type"] ]
        # different type includes: REG, IMM, MEM_BASE, MEM_INDEX, MEM_DISP, JUMPS 

    @property
    def isFullMatch(self):
        return self.matchtype=="FULL"


    @property
    def isPartialMatch(self):
        return self.matchtype=="PARTIAL"
    
    @property
    def isPartialMatch2(self):
        return self.matchtype=="PARTIAL2"

    def setMatchType(self, matchtype, matchedItem):
        self.matchtype = matchtype
        self.matchedItem = matchedItem

    def __eq__(self, other):
        return (self.compbytes == other.compbytes)

class Register(object):
    # al ax ah eax rax
    # bl bx bh ebx rbx
    mark = None
    _Reg64Mark = _Reg32Mark = _Reg16Mark = _Reg8Mark = False
    flag = "REG"

    def __init__(self, regName: str):
        self.realType = regName
        self.setType(regName)
        self.setMark(regName)

    def __eq__(self, var):
        try:
            if self.flag == var.flag and self.type == var.type:# and self.value == var.value:
                return True
            else:
                return False
        except:
            return False

    @property
    def isReg64(self):
        return self._Reg64Mark

    @property
    def isReg32(self):
        return self._Reg32Mark

    @property
    def isReg16(self):
        return self._Reg16Mark

    @property
    def isReg8(self):
        return self._Reg8Mark

    def setType(self, reg: str):
        if IS_X32ARCH:
            if reg in EAX_LIST:
                self.type = "eax"
            elif reg in EBX_LIST:
                self.type = "ebx"
            elif reg in ECX_LIST:
                self.type = "ecx"
            elif reg in EDX_LIST:
                self.type = "edx"
            elif reg in EBP_LIST:
                self.type = "ebp"
            elif reg in ESI_LIST:
                self.type = "esi"
            elif reg in EDI_LIST:
                self.type = "edi"
            elif reg in ESP_LIST:
                self.type = "esp"
            else:
                self.type = reg
        else:
            if reg in EAX_LIST:
                self.type = "rax"
            elif reg in EBX_LIST:
                self.type = "rbx"
            elif reg in ECX_LIST:
                self.type = "rcx"
            elif reg in EDX_LIST:
                self.type = "rdx"
            elif reg in EBP_LIST:
                self.type = "rbp"
            elif reg in ESI_LIST:
                self.type = "rsi"
            elif reg in EDI_LIST:
                self.type = "rdi"
            elif reg in ESP_LIST:
                self.type = "rsp"
            else:
                self.type = reg

    def setMark(self, reg: str):
        if reg in REG64_LIST:
            self.mark = 64
            self._Reg32Mark = True
        elif reg in REG32_LIST:
            self.mark = 32
            self._Reg32Mark = True
        elif reg in REG16_LIST:
            self.mark = 16
            self._Reg16Mark = True
        elif reg in REG8_LIST:
            self.mark = 8
            self._Reg8Mark = True

    def setValue(self, regValue: int):
        #TODO for different size 在setmark或之前判断是哪个寄存器，然后加载对应的符号运算方法，实际上就是不同的位，直接进行异或就行
        self.value = regValue

class Memory(object):
    flag = "MEM"

    def __init__(self, operand, memAddr):
        self.type = operand
        #self.memAddr = memAddr

    def __eq__(self, var):
        try:
            if self.flag == var.flag and self.type == var.type:
                return True
            else:
                return False
        except:
            return False

class Immediate(object):
    flag = "IMM"

    def __init__(self, imm):
        self.type = None
        self.value = imm

    def __eq__(self, var):
        try:
            if self.flag == var.flag and self.type == var.type:
                return True
            else:
                return False
        except:
            return False


class Instruction(object):
    """
    Instruction context order:
        addr asm eax ebx ecx edx esi edi esp ebp eflags read write
    """

    # instruction destination and source
    insn = dst = src = None
    # whether read/write memory
    readmem = False
    writemem = False
    # index in the INS_List
    index = None

    def __init__(self, instruction, index: int, proj):
        super().__init__()
        self.index = index
        self.proj = proj
        self.insn = instruction
        self._setSrcDst()

    def _bitMask(self, target: Register, ins: str):
        value = int(ins.split(',')[-1], 16)  # 取立即数
        if target.mark==16:
            return ins.replace(hex(value), hex(value & 0xffff)) # 高位清空，保证数据一致

        elif target.mark==8:
            return ins.replace(hex(value), hex(value & 0xff))
        return ins

    def rewrite(self, ins: str, proj, flag=None):
        if flag=="IMM":
            # mask the immediate to correct size
            if self.src.flag=="REG":
                # l.error(ins)
                ins = self._bitMask(self.src, ins)

            elif self.dst.flag=="REG" and self.mnemonic=="xchg":
                # l.error(ins)
                ins = self._bitMask(self.dst, ins)

        # l.error(ins)
        insbytes = proj.arch.asm(ins, self.addr, as_bytes=True)  # problem
        self.insbytes = insbytes
        self.insn = list(proj.arch.capstone.disasm(insbytes,self.addr))[0]
        # self.raddr = 0
        # self.waddr = 0
        self._setSrcDst()

    def __getattr__(self, item):
        # Methods of CsInsn
        if item in ('__str__', '__repr__'):
            return self.__getattribute__(item)
        if hasattr(self.insn, item):
            return getattr(self.insn, item)
        l.warning("no such keyword {}".format(item))
        raise AttributeError()
        
    def __repr__(self):
        return '<Instruction "%s" for %#x>' % (self.mnemonic, self.address)

    def _setSrcDst(self):
        #
        if len(self.insn.operands)>2:
            # more than two operand
            #TODO new handlers
            self.src = self._constructPara(self.insn.operands[2])
            self.dst = self._constructPara(self.insn.operands[0])
            pass
        elif len(self.insn.operands)==2:
            # two operand
            if self.insn.mnemonic == "xchg":
                self.src, self.dst = [self._constructPara(i) for i in self.insn.operands]
            elif "rep" in self.insn.mnemonic:
                self.dst, self.src = [self._constructPara(i,order=index,mode="M2M") for index,i in enumerate(self.insn.operands)]
            # elif "mov" in self.insn.mnemonic and self.waddr != 0 and self.raddr != 0:   # 都是内存的mov情况
            #     mem_marks = re.findall('\[.*?\]',self.insn.op_str)
            #     self.dst = Memory(mem_marks[0], self.waddr)
            #     self.src = Memory(mem_marks[1], self.raddr)
            else:
                self.dst, self.src = [self._constructPara(i) for i in self.insn.operands]
        elif len(self.insn.operands)==1:
            # one operand
            # if "div" in self.insn.mnemonic:
            #     # div idiv
            #     operandsize = self.insn.operands[0].size
            #     if operandsize == 8:
            #         self.src = [Register('rax'), Register('rdx'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('rax'), Register('rdx')]
            #     elif operandsize == 4:
            #         self.src = [Register('eax'), Register('edx'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('eax'), Register('edx')]
            #     elif operandsize == 2:
            #         self.src = [Register('ax'), Register('dx'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('ax'), Register('dx')]
            #     elif operandsize == 1:
            #         self.src = [Register('ax'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('ax')]
            #     return

            # elif "mul" in self.insn.mnemonic:
            #     # mul imul
            #     operandsize = self.insn.operands[0].size
            #     if operandsize == 8:
            #         self.src = [Register('rax'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('rax'), Register('rdx')]
            #     elif operandsize == 4:
            #         self.src = [Register('eax'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('eax'), Register('edx')]
            #     elif operandsize == 2:
            #         self.src = [Register('eax'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('ax'), Register('dx')]
            #     elif operandsize == 1:
            #         self.src = [Register('ax'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('ax')]
            #     return

            # if self.insn.operands[0].type==3:
            #     # MEM 3
            #     # push/pop [mem] 
            #     if self.insn.mnemonic in ["push"]:
            #         self.src = Memory(re.search('\[.*\]',self.insn.op_str), 0)
            #         self.dst = Memory("esp", 0)
            #     else:
            #         self.src = Memory("esp", 0)
            #         self.dst = Memory(re.search('\[.*\]',self.insn.op_str), 0)  
            if self.insn.mnemonic in ["push"]:
                # write to memory
                self.src = self._constructPara(self.insn.operands[0])
                self.dst = Memory("[esp]", 0)
            elif self.insn.mnemonic in ["pop"]:
                # read from memory
                self.dst = self._constructPara(self.insn.operands[0])
                self.src = Memory("[esp]", 0)
            else:
                # other operation (e.g. not)
                self.src = self.dst = self._constructPara(self.insn.operands[0])

        elif len(self.insn.operands)==0:
            # no operand (e.g. nop, pushfd)
            if self.insn.mnemonic in ["pushfd"]:
                    # write to memory
                    self.src = Register('eflags')
                    self.dst = Memory('[esp]', 0)
            elif self.insn.mnemonic in ["popfd"]:
                    # read from memory
                    self.dst = Register('eflags')
                    self.src = Memory('[esp]', 0)
            
            elif self.insn.mnemonic in ["cwd", "cdq"]:
                self.src = Register('eax')
                self.dst = Register('edx')
            # elif self.insn.mnemonic == "rdtsc":
            #     self.dst = Register('eax')
            #     self.src = Memory(None, self.raddr)
            elif self.insn.mnemonic == "lahf":
                self.src = Register('eflags')
                self.dst = Register('eax')
            elif self.insn.mnemonic == "sahf":
                self.dst = Register('eflags')
                self.src = Register('eax')
            elif self.insn.mnemonic in ["aaa", "aad", "aam", "aas","daa","das"]:
                self.dst = Register('eax')
                self.src = Register('eax')
            elif self.insn.mnemonic == "lodsd":
                self.dst = Memory('[esi]',0)
                self.src = Memory('[eax]',0)
            elif self.insn.mnemonic == "rdtsc":
                self.dst = Register('edx')
                self.src = Memory('[time]',0)
            else:
                self.src = self.dst = None
                srcReg = self.insn.regs_read
                dstReg = self.insn.regs_write
                if len(srcReg) > 0:
                    # no operands but have register access e.g. cbw/cwde/cdqe
                    srcReg=Register(self.insn.reg_name(srcReg[0]))
                    self.src = srcReg
                if len(dstReg) > 0:
                    dstReg=Register(self.insn.reg_name(dstReg[0]))
                    self.dst = dstReg
                # self.src = self.dst = None
        if self.dst==None or self.src == None:
            print(self.insn.mnemonic)

        if self.dst and self.dst.flag=="MEM":
            self.readmem = True
        if self.src and self.src.flag=="MEM":
            self.writemem = True 

    def _constructPara(self, operand, mode="", order=0):
        memaddr = None
        # if mode=="M2M":
        #     memaddr = [self.waddr, self.raddr][order]
        # else:
        #     if self.waddr!=0:
        #         memaddr = self.waddr
        #     elif self.raddr!=0:
        #         memaddr = self.raddr

        if operand.type==3:
            # X86_OP_MEM = 3
            return Memory(re.search('\[.*\]',self.insn.op_str).group(0), memaddr) # origin
            # return Memory(re.search('\[.*?\]',self.insn.op_str).group(0), memaddr)
        elif operand.type==2:
            # X86_OP_IMM = 2
            return Immediate(operand.imm)
        elif operand.type==1:
            # X86_OP_REG = 1
            regName = self.insn.reg_name(operand.reg)
            tmp = Register(regName)
            return tmp
    
    def isDataTransfer(self, flag="ALL"):
        if flag=="ALL":
            tins = ["push", "pop", "pushfd", "popfd"]
        elif flag=="IN":
            tins = ["push", "pushfd"]
        elif flag=="OUT":
            tins = ["pop", "popfd"]
        if "mov" in self.insn.mnemonic or self.insn.mnemonic in tins:
            return True
        else:
            return False
    
    @property
    def isReadMemory(self):
        if self.readmem:
            return True
        else:
            return False
    
    @property
    def isWriteMemory(self):
        if self.writemem:
            return True
        else:
            return False

class ValueLabel(object):

    def __init__(self, name: str, ins:Instruction, raddr=None, waddr=None,):
        self.operation = False
        self.name = name
        self.raddr = raddr
        self.waddr = waddr
        self._op_list = []
        self.flag = True
        self.index = ins.index
        self._op_list.append(ins)
        self.overwrited = False
        self.start = 0
        self.end = 0
        pass

    def setRaddr(self, raddr: int):
        self.raddr = raddr

    def setWaddr(self, waddr: int):
        self.waddr = waddr

    def addOP(self, ins: Instruction):
        self._op_list.append(ins)

    def updateSE(self):
        self.start = self._op_list[0].index
        self.end = self._op_list[-1].index
