/*
 * A pin tool to record all instructions in a binary execution.
 *
 */

#include <stdio.h>
#include <pin.H>
#include <map>
#include <iostream>
#include <string>
#include <fstream>
#include "BlockInfo.h"
#include "SecInfo.h"

namespace WINDOWS
{
#include <C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\um\Windows.h>
}



#define __readable__

using std::ifstream;
using std::string;


BlockInfo* info;
const char* prelogfile = "prelogfile.txt";
ADDRINT startaddr=0;
bool recording = false;
PIN_LOCK globalLock;
static bool isclose = false;
ADDRINT ADRESS_LIMIT = 0xffffff;

std::ofstream fileout;
//FILE* fp;

using namespace std;

ADDRINT filter_ip_low, filter_ip_high;

std::string target_name;

KNOB<string> KnobInputFile(KNOB_MODE_WRITEONCE, "pintool",
    "i", "", "prelog file");

std::map<ADDRINT, ADDRINT> t_inscounter;
std::map<ADDRINT, ADDRINT> t_startaddr;
std::map<ADDRINT, BlockInfo*> bbcalled;
std::map<string, SecInfo*> seclimited;

PIN_LOCK pinLock;


/*VOID* MemAlloc(size_t size)
{
    void* pageFrameStart = NULL;
    OS_AllocateMemory(NATIVE_PID_CURRENT,
        OS_PAGE_PROTECTION_TYPE_READ | OS_PAGE_PROTECTION_TYPE_WRITE,
        size, OS_MEMORY_FLAGS_PRIVATE, &pageFrameStart);
    return pageFrameStart;
}*/
VOID* MemAlloc(size_t size)
{
    return WINDOWS::VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
}
/*VOID MemFree(VOID* addr, size_t size)
{
    OS_FreeMemory(NATIVE_PID_CURRENT, addr, size);
}*/
VOID MemFree(VOID* addr, size_t size)
{
    WINDOWS::VirtualFree(addr, size, MEM_RELEASE);
}

CHAR* value = (CHAR*)MemAlloc(0x1000);


EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v)
{
    ADDRINT erroraddr = PIN_GetExceptionAddress(pExceptInfo);
    EXCEPTION_CODE c = PIN_GetExceptionCode(pExceptInfo);
    EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);
    std::cout << "Exception class " << PIN_ExceptionToString(pExceptInfo) << "\n";
    std::cout << "Exception addr" << hex << erroraddr << endl;
    int test;
    cin >> test;
    return EHR_UNHANDLED;
}



bool AreOnSamePage(ADDRINT a, ADDRINT b) {
    /*SYSTEM_INFO sysInfo;

    GetSystemInfo(&sysInfo);
    const size_t page_size = sysInfo.dwPageSize;*/
    const size_t page_size = 4096;
    if (a / page_size == b / page_size) {
        return true;
    }
    else {
        return false;
    }
}

bool isMemExecutable(ADDRINT addr)
{
    OS_MEMORY_AT_ADDR_INFORMATION meminfo = {};
    NATIVE_PID pid = 0;
    OS_GetPid(&pid);
    OS_QueryMemory(pid, (VOID*)addr, &meminfo);
    if ((meminfo.Protection & OS_PAGE_PROTECTION_TYPE_EXECUTE) == OS_PAGE_PROTECTION_TYPE_EXECUTE) {
        //cout << meminfo.Protection << " " << OS_PAGE_PROTECTION_TYPE_EXECUTE << endl;
        //PIN_ExitProcess(0);
        return true;
    }
    else {
        return false;
    }
}

void CloseFile()
{
    std::cout << "close file" << endl;
    if (!isclose)
    {
        fileout.close();
        isclose = true;
    }
}

// Trivial analysis routine to pass its argument back in an IfCall so that we can use it
// to control the next piece of instrumentation.
static ADDRINT returnArg(BOOL arg)
{
    return arg;
}

static void updateBBLCalled(ADDRINT startaddr, ADDRINT endaddr, ADDRINT threadid, ADDRINT tag) {
    //PIN_GetLock(&globalLock, threadid + 1);
    ADDRINT tmp_startaddr = 0;
    ADDRINT tmp_inscounter = 0;

    /* 
        Get startaddr of basic block for current thread
    */
    if (t_startaddr.find(threadid) != t_startaddr.end())
        tmp_startaddr = t_startaddr[threadid];

    /*
        Get inscounter of basic block for current thread
    */
    if (t_inscounter.find(threadid) != t_inscounter.end())
        tmp_inscounter = t_inscounter[threadid];

    unsigned int bufsize = endaddr - tmp_startaddr;

    /* 
        Create new basic block for current thread
     */
    if (bbcalled.find(tmp_startaddr) == bbcalled.end()) {
        bbcalled.insert(std::pair<ADDRINT, BlockInfo*>(tmp_startaddr, new BlockInfo(tmp_startaddr)));
    }
        
    bbcalled[tmp_startaddr]->calledtime = bbcalled[tmp_startaddr]->calledtime + 1;
    bbcalled[tmp_startaddr]->endaddr = endaddr;

    if (bufsize > 0x1000) {
        cout <<  "[" << tag << "] " << dec << threadid << ": "<< hex << static_cast<void*>(value) << ", " << tmp_startaddr << ", " << endaddr << ", " << bufsize << endl;
        bbcalled[tmp_startaddr]->bytesstring << "";
        return;
    }

    ADDRINT* addr_ptr = (ADDRINT*)tmp_startaddr;
    if (bbcalled[tmp_startaddr]->bytesstring.str().empty()){
        //PIN_LockClient();
        PIN_SafeCopy(value, addr_ptr, bufsize);
        //PIN_UnlockClient();

        int i = 0;
        for (i = 0; i < bufsize; ++i) {
            bbcalled[tmp_startaddr]->bytesstring << setw(2) << setfill('0') << hex << (0xff & (unsigned int)value[i]);
        }

        // update inscounter for bsic block
        bbcalled[tmp_startaddr]->inscounter = tmp_inscounter;
    }
    //PIN_ReleaseLock(&globalLock);

}

static void OnException(THREADID threadIndex,
    CONTEXT_CHANGE_REASON reason,
    const CONTEXT* ctxtFrom,
    CONTEXT* ctxtTo,
    INT32 info,
    VOID* v) {
    if (reason){// == CONTEXT_CHANGE_REASON_EXCEPTION || reason == CONTEXT_CHANGE_REASON_CALLBACK) {
        /* 
            Many packers trigger exception for jumping to other instructions.
            e.g. armadillo will use "pop dword ptr [eax]" (eax=0) 
        */

        std::cout << "catched error" << endl;
        UINT32 exceptionCode = info;
        //EXCEPTION_CODE c = PIN_GetExceptionCode(info);
        //EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);
        //cout << PIN_ExceptionToString(info) << endl;
        //return EHR_UNHANDLED;

        //std::cout << ctxtFrom << endl;
        //PIN_GetLock(&globalLock, threadIndex + 1);

        ADDRINT tmp_incounter = 0;
        if (t_inscounter.find(threadIndex) != t_inscounter.end())
            tmp_incounter = t_inscounter[threadIndex];

        if (ctxtFrom != 0x0) {
            ADDRINT addr = PIN_GetContextReg(ctxtFrom, REG_EIP);
            //std::cout << addr << endl;


            if (tmp_incounter > 0) { // inscounter > 3 || (bufsize > 6 && inscounter > 2) || (bufsize > 4 && inscounter == 1)) { //|| (inscounter==0 && bufsize>4) ) {
                cout << hex << startaddr << "," << addr << endl;
                updateBBLCalled(startaddr, addr, threadIndex, 3);
            }
        }
      
        // update inscounter for each thread
        if (t_inscounter.find(threadIndex) != t_inscounter.end())
            t_inscounter[threadIndex] = 0;
        //PIN_ReleaseLock(&globalLock);

    }

}

void INScounter(ADDRINT addr, CONTEXT* fromctx, ADDRINT raddr, ADDRINT waddr, UINT32 repCount, ADDRINT threadid) {
    //fileout << "next insn:" << hex << addr << " " << inscounter << endl << flush;
    PIN_GetLock(&globalLock, threadid + 1);
    bool isrecord = false;

    if (t_inscounter.find(threadid) == t_inscounter.end())
        t_inscounter.insert(std::pair<ADDRINT, ADDRINT>(threadid, 0));

    
    /*
    * Recording the start of basic block. Based on inscounter.
    * Record at thread level.
    */
    if (t_inscounter[threadid] == 0) {

        startaddr = addr;
        if (t_startaddr.find(threadid) == t_startaddr.end()) {
            t_startaddr.insert(std::pair<ADDRINT, ADDRINT>(threadid, addr));
        }
        else {
            t_startaddr[threadid] = addr;
        }

        /*
        * If the basic block shows agi
        */
        if (bbcalled.find(startaddr) != bbcalled.end()) {
            bbcalled[startaddr]->calledtime = bbcalled[startaddr]->calledtime + 1;
        }
        else {
            PIN_LockClient();
            //RTN target = RTN_FindByAddress(addr);
            IMG target_img = IMG_FindByAddress(addr);
            PIN_UnlockClient();
            if (IMG_Valid(target_img)) {
                //if (RTN_Valid(target)) {

                if (!IMG_IsMainExecutable(target_img)) {
                    // ASProtect is not main executable and have false checked
                    t_inscounter[threadid] = 0;
                    PIN_ReleaseLock(&globalLock);
                    return;
                }
                else {
                    isrecord = true;
                }
            }
            else if (addr < ADRESS_LIMIT) {
                isrecord = true;
            }

            if (isrecord && addr < ADRESS_LIMIT) {
                //cout << "[!]" << hex << startaddr << endl;
                bbcalled.insert(std::pair<ADDRINT, BlockInfo*>(addr, new BlockInfo(addr)));
                if (bbcalled.find(addr) != bbcalled.end()) {
                    bbcalled[addr]->calledtime = bbcalled[addr]->calledtime + 1;
                }
                else {
                    cout << "[!] insert failed" << endl;
                }
                //cout << "msize: " << dec << bbcalled.size() << endl;
            }
        }
    }

    ADDRINT tmp_startaddr = 0;
    if (t_startaddr.find(threadid) != t_startaddr.end())
        tmp_startaddr = t_startaddr[threadid];

    /*
    * Record behaviors of reading and writing memory and corresponding addr.
    */
    if ((raddr != 0 || repCount != 0 || waddr != 0) && bbcalled.find(tmp_startaddr) != bbcalled.end()) {
        // TODO  length check 
        // cout << "[!]start " << dec << threadid << ": " << hex << addr << ", " << tmp_startaddr << "," << startaddr << endl;


        if (raddr != 0) {
            map<string, SecInfo*>::iterator iter = seclimited.begin();

            while (iter != seclimited.end()) {
                if (raddr >= iter->second->startaddr && raddr <= iter->second->endaddr) {
                    if (bbcalled[tmp_startaddr]->type.empty())
                        bbcalled[tmp_startaddr]->type = iter->second->type;
                    else if (bbcalled[tmp_startaddr]->type.find(iter->second->type) == string::npos)
                        bbcalled[tmp_startaddr]->type += iter->second->type;
                }
                iter++;
            }
            /*
            if (bbcalled[startaddr]->readstartaddr == 0) {
                bbcalled[startaddr]->readstartaddr = raddr;
            }
            else {
                bbcalled[startaddr]->readendaddr = raddr;
            }*/
        }

        if (repCount != 0) {
            //cout << "[+]FOUND REP " << hex << addr << ", " << waddr << ", " << startaddr << "," << inscounter << "," << repCount << endl;
            bbcalled[tmp_startaddr]->calledtime = bbcalled[tmp_startaddr]->calledtime + repCount;
        }

        if (waddr != 0) {
            map<string, SecInfo*>::iterator iter = seclimited.begin();

            while (iter != seclimited.end()) {
                if (waddr >= iter->second->startaddr && waddr <= iter->second->endaddr) {
                    if (bbcalled[tmp_startaddr]->type.empty())
                        bbcalled[tmp_startaddr]->type = iter->second->type;
                    else if (bbcalled[tmp_startaddr]->type.find(iter->second->type) == string::npos)
                        bbcalled[tmp_startaddr]->type += iter->second->type;
                }
                iter++;
            }

            if (bbcalled[tmp_startaddr]->type.find('m') == string::npos && isMemExecutable(waddr)) {
                bbcalled[tmp_startaddr]->type += "m";
            }
            
            /*
            * Handling for DEP off packers. e.g., MEW, pelock
            */
            if (bbcalled[tmp_startaddr]->type.find('nm') == string::npos){
               PIN_LockClient();
               IMG origin_img = IMG_FindByAddress(waddr);
               PIN_UnlockClient();

                if (IMG_Valid(origin_img)) {
                    if (IMG_IsMainExecutable(origin_img)) {

                        //cout << "[searchn]" << hex << waddr << endl;//dec << ", " << IMG_IsMainExecutable(IMG_FindByAddress(waddr)) << endl;
                        bbcalled[tmp_startaddr]->type += "nm";
                    }
                }
            }

            if (bbcalled[tmp_startaddr]->writestartaddr == 0) {
                bbcalled[tmp_startaddr]->writestartaddr = waddr;
            }
            else {
                bbcalled[tmp_startaddr]->writeendaddr = waddr;
            }
            
        }
        // cout << "[!]finished" << endl;
    }

    // cout << "[@] " << hex << addr << endl;
    t_inscounter[threadid] += 1;

    PIN_ReleaseLock(&globalLock);
}

void getINSBytes(ADDRINT addr, CONTEXT* fromctx, ADDRINT insize, ADDRINT threadid) {
    // cout << "controlflow insn:" << hex << addr << endl;
    PIN_GetLock(&globalLock, threadid + 1);

    ADDRINT tmp_startaddr = 0;

    if (t_startaddr.find(threadid) != t_startaddr.end())
        tmp_startaddr = t_startaddr[threadid];
    else{
        t_startaddr.insert(std::pair<ADDRINT, ADDRINT>(threadid, addr));
        tmp_startaddr = addr;
    }

    bool record = false;

    if (t_inscounter.find(threadid) == t_inscounter.end())
        t_inscounter.insert(std::pair<ADDRINT, ADDRINT>(threadid, 0));


    t_inscounter[threadid] += 1;
    if (t_inscounter[threadid] > 1){ // inscounter > 3 || (bufsize > 6 && inscounter > 2) || (bufsize > 4 && inscounter == 1)) { //|| (inscounter==0 && bufsize>4) ) {
        if (bbcalled.find(tmp_startaddr) != bbcalled.end() && bbcalled[tmp_startaddr]->endaddr != 0)
        {
            t_inscounter[threadid] = 0;
            PIN_ReleaseLock(&globalLock);

            return;
        }

        PIN_LockClient();
        IMG target_img = IMG_FindByAddress(addr);
        PIN_UnlockClient();

        if (IMG_Valid(target_img)) {

            if (!IMG_IsMainExecutable(target_img)) {
                // ASProtect is not main executable and have false checked
                t_inscounter[threadid] = 0;
                PIN_ReleaseLock(&globalLock);

                return;
            }
            else {
                record = true;
            }
        }  else if (addr < ADRESS_LIMIT) {
            record = true;
        }

        if (record && tmp_startaddr < ADRESS_LIMIT) {
            updateBBLCalled(tmp_startaddr, addr + insize, threadid, 1);
        }
        
    }
    else {
        // single jmp

        if (bbcalled.find(addr) != bbcalled.end() && bbcalled[addr]->endaddr != 0)
        {
            bbcalled[addr]->calledtime = bbcalled[addr]->calledtime + 1;
        }

        else if (addr < ADRESS_LIMIT && insize != 1)
        {
            //cout << hex << addr << "some, " << dec << insize << endl;
            t_startaddr[threadid] = addr;
            updateBBLCalled(addr, addr + insize, threadid, 2);
        }
    }

    t_inscounter[threadid] = 0;
    PIN_ReleaseLock(&globalLock);
}


static void instruction(INS ins, void* v)

{
    ADDRINT addr = INS_Address(ins);


    if (addr <= 0x10000000)
    {


        if (startaddr == 0) {
            startaddr = addr;
        }
        bool isAnchor = false;

        if (INS_IsControlFlow(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getINSBytes, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, INS_Size(ins), IARG_THREAD_ID, IARG_END);
        }
        else {

            // INS_HasExplicitMemoryReference -> only consider memory operation in operand. omit stack operation (e.g. ret, push)
            if (!INS_IsStackWrite(ins) && !INS_IsStackRead(ins) && INS_IsMemoryWrite(ins) && INS_IsMemoryRead(ins) ) //!INS_IsStackRead(ins) &&
            {
                
                /*if (INS_IsMemoryRead(ins) && INS_IsMemoryWrite(ins))
                {
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INScounter, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_END);
                }
                else if (INS_IsMemoryRead(ins))
                {
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INScounter, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_ADDRINT, 0, IARG_END);
                }*/
                //if (INS_IsMemoryWrite(ins))
                //{
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INScounter, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_ADDRINT, 0, IARG_THREAD_ID, IARG_END);

                //}
                    if (INS_HasRealRep(ins)) {
                        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)returnArg, IARG_FIRST_REP_ITERATION, IARG_END);
                        INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)INScounter,
                            IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA,
                            IARG_REG_VALUE, INS_RepCountRegister(ins),
                            IARG_END);
                    }
            }
            else if (!INS_IsStackRead(ins) && INS_IsMemoryRead(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INScounter, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_ADDRINT, 0, IARG_ADDRINT, 0, IARG_THREAD_ID, IARG_END);
            }
            else if (!INS_IsStackWrite(ins) && INS_IsMemoryWrite(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INScounter, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_MEMORYWRITE_EA, IARG_ADDRINT, 0, IARG_THREAD_ID, IARG_END);
            }
            else
            {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INScounter, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_ADDRINT, 0, IARG_ADDRINT, 0, IARG_THREAD_ID, IARG_END);
            }
            
        }

    }
}


VOID beforeVirtualProtect(CHAR* name, ADDRINT addr, ADDRINT size, ADDRINT flNewProtect, ADDRINT lpflOldProtect)
{
    if (flNewProtect == 0x40 || flNewProtect == 0x20) {
        // PAGE_EXECUTE_READWRITE  0x40 
        // PAGE_EXECUTE_READ       0x20
        std::cout << name << " : " << hex << addr << dec << "(" << size << ")" << " : " << hex << flNewProtect << "-" << lpflOldProtect << endl;
        map<ADDRINT, BlockInfo*>::iterator newiter = bbcalled.begin();

        while (newiter != bbcalled.end()) {
            if (newiter->second->type.empty() && newiter->second->writeendaddr>= addr && newiter->second->writeendaddr <= addr+size) {
                newiter->second->type = "nm";
            }
            newiter++;
        }
    }

}

VOID beforeVirtualProtectEx(CHAR* name, ADDRINT hProcess, ADDRINT addr, ADDRINT size, ADDRINT flNewProtect, ADDRINT lpflOldProtect)
{
    std::cout << name << " : " << hex << addr << dec << "(" << size << ")" << " : " << hex << flNewProtect << "-" << lpflOldProtect << endl;
    /*
    if (flNewProtect == 0x40 || flNewProtect == 0x20) {
        // PAGE_EXECUTE_READWRITE  0x40 
        // PAGE_EXECUTE_READ       0x20
        std::cout << name << " : " << hex << addr << dec << "(" << size << ")" << " : " << hex << flNewProtect << "-" << lpflOldProtect << endl;

        map<ADDRINT, BlockInfo*>::iterator newiter = bbcalled.begin();

        while (newiter != bbcalled.end()) {
            if (newiter->second->type.empty() && newiter->second->writeendaddr >= addr && newiter->second->writeendaddr <= addr + size) {
                newiter->second->type = "nm";
            }
            newiter++;
        }
      
    }
      */
}

VOID ImageHandler(IMG img, VOID* v)
{
    RTN vpRtn = RTN_FindByName(img, "VirtualProtect");
    RTN vpexRtn = RTN_FindByName(img, "VirtualProtectEx");

    if (RTN_Valid(vpRtn))
    {
        cout << "Find VirtualProtect" << endl;

        RTN_Open(vpRtn);

        // Instrument malloc() to print the input argument value and the return value.
        RTN_InsertCall(vpRtn, IPOINT_BEFORE, (AFUNPTR)beforeVirtualProtect,
            IARG_ADDRINT, "VirtualProtect",
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
            IARG_END);


        RTN_Close(vpRtn);
    }


    if (RTN_Valid(vpexRtn))
    {
        cout << "Find VirtualProtectEx" << endl;

        RTN_Open(vpexRtn);

        // Instrument malloc() to print the input argument value and the return value.
        RTN_InsertCall(vpexRtn, IPOINT_BEFORE, (AFUNPTR)beforeVirtualProtectEx,
            IARG_ADDRINT, "VirtualProtectEx",
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
            IARG_END);


        RTN_Close(vpexRtn);
    }
}

/* ===================================================================== */
/* Fini Function ----- Recording to File                                 */
/* ===================================================================== */
VOID on_fini(void* v)
{
    std::cout << "Finished" << endl;
    map<ADDRINT, BlockInfo*>::iterator iter = bbcalled.begin();

//    while (iter != bbcalled.end()) {        
//        fileout << hex << iter->second->startaddr << "-" << hex << iter->second->endaddr << dec << "," << iter->second->calledtime << "," << iter->second->inscounter << "," << iter->second->bytesstring.str().c_str() << "," << iter->second->type << ",WRITE:" << hex << iter->second->writestartaddr << "-" << hex << iter->second->writeendaddr << endl << flush;
//        iter++;
//    }
    while (iter != bbcalled.end()) {
        if (iter->second->endaddr != 0) {
            fileout << hex << iter->second->startaddr << "-" << hex << iter->second->endaddr << dec << "," << iter->second->calledtime << "," << iter->second->inscounter << "," << iter->second->bytesstring.str().c_str() << "," << iter->second->type << ",WRITE:" << hex << iter->second->writestartaddr << "-" << hex << iter->second->writeendaddr << endl << flush;
       }
        iter++;
    }


    CloseFile();
}


VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    PIN_GetLock(&pinLock, threadid + 1);
    cout<< "thread begin"<< threadid << "\n" << endl;
    PIN_ReleaseLock(&pinLock);
}

VOID ThreadAttach(THREADID threadid, CONTEXT* ctxt, VOID* v)
{
    PIN_GetLock(&pinLock, threadid + 1);
    cout << "thread attach" << threadid << "\n"<< endl;
    PIN_ReleaseLock(&pinLock);
}

// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    PIN_GetLock(&pinLock, threadid + 1);
    cout<< "thread end %d code %d" << threadid << "\n" << endl;
    PIN_ReleaseLock(&pinLock);
}


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    PIN_ERROR("This tool prints a log of image load and unload events\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

std::string extractFilename(const std::string& filename)
{
    unsigned int lastBackslash = filename.rfind("\\"); // windows
    //unsigned int lastBackslash = filename.rfind("/"); // Linux
    unsigned int lastdot = filename.rfind(".");

    if (lastBackslash != std::string::npos && lastdot != std::string::npos)
    {
        return filename.substr(lastBackslash + 1, lastdot - lastBackslash - 1);
    }
    else if (lastBackslash == std::string::npos && lastdot != std::string::npos)
    {
        return filename.substr(0, lastdot);
    }
    else if (lastdot == std::string::npos && lastBackslash != std::string::npos)
    {
        return filename.substr(lastBackslash + 1);
    }
    else
    {
        return filename;
    }
}

void initLimitScope(const std::string& filename)
{
    cout << filename << endl;

    ifstream file(filename.c_str(), ifstream::in);
    while (file.good()) {
        string lines;
        string secname;
        string number;
        getline(file, lines);
        cout << lines << endl;
        istringstream ss(lines);
        getline(ss, secname, ',');
        seclimited.insert(std::pair<string, SecInfo*>(secname, new SecInfo(secname)));
        getline(ss, number, ',');
        seclimited[secname]->startaddr = (ADDRINT) atoi(number.c_str());
        getline(ss, number, ',');
        seclimited[secname]->endaddr = (ADDRINT)atoi(number.c_str());
        getline(ss, number, ',');
        seclimited[secname]->type = number;
    }
    //cout << filename << endl;

}


int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv))
        return Usage();


    char* tracefile = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--") == 0)
        {
            tracefile = argv[i + 1];
            break;
        }
    }

    target_name = extractFilename(tracefile) + ".log";

    if (!KnobInputFile.Value().empty()) 
    {
        initLimitScope(KnobInputFile.Value());
    }
    else {
        initLimitScope(extractFilename(tracefile) + ".prelog");
    }

    KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
        "o", target_name, "trace file");

    //fp = fopen(KnobOutputFile.Value().c_str(), "w");
    fileout.open(KnobOutputFile.Value().c_str());


    PIN_InitSymbols();

    PIN_AddContextChangeFunction(OnException, 0);

    // IMG_AddInstrumentFunction(ImageHandler, 0);

    INS_AddInstrumentFunction(instruction, 0);

    PIN_AddPrepareForFiniFunction(on_fini, 0);


    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadAttachFunction(ThreadAttach, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);

    PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);
    
    PIN_StartProgram(); // Never returns

    CloseFile();
    return 0;
}