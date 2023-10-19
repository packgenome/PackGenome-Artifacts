
class SecInfo {
public:
    ADDRINT startaddr;
    ADDRINT endaddr;
    std::string type;
    std::string secname;

    SecInfo(std::string secname);
   /* BlockInfo(ADDRINT addr) {
        startaddr = addr;
    }*/
};


SecInfo::SecInfo(std::string secname) {
    secname = secname;
    startaddr = 0;
    endaddr = 0;
    type = "";
}
