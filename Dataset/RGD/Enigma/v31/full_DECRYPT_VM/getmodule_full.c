#include <stdio.h>
#include "windows.h"

// INCLUDE


// DEFINE

int main()
{
// BEGIN 1
#include "J:\packers\enigma\enigma3.10\EnigmaSDK\VC\decrypt_on_execute_begin.inc"
    HMODULE handle = GetModuleHandle(NULL);
// END 1
#include "J:\packers\enigma\enigma3.10\EnigmaSDK\VC\decrypt_on_execute_end.inc"

// BEGIN 2
#include "J:\packers\enigma\enigma3.10\EnigmaSDK\VC\vm_begin.inc"
    printf("%p\n", handle);
// END 2
#include "J:\packers\enigma\enigma3.10\EnigmaSDK\VC\vm_end.inc"

    return 0;
}