
class BlockInfo {
public:
    ADDRINT startaddr;
    ADDRINT endaddr;
    unsigned int calledtime;
    unsigned int inscounter;
    ADDRINT readstartaddr;
    ADDRINT readendaddr;
    ADDRINT writestartaddr;
    ADDRINT writeendaddr;
    std::stringstream bytesstring;
   std::string type;

    BlockInfo(ADDRINT addr);
   /* BlockInfo(ADDRINT addr) {
        startaddr = addr;
    }*/
};


BlockInfo::BlockInfo(ADDRINT addr) {
    startaddr = addr;
    endaddr = 0;
    calledtime = 0;
    inscounter = 0;
    readstartaddr = 0;
    readendaddr = 0;
    writestartaddr = 0;
    writeendaddr = 0;
    type = "";
}
