#include <stdio.h>

#include "windows.h"
// INCLUDE


// DEFINE


int main(void)
{

// BEGIN 1
#include "J:\packers\enigma\enigma3.10\EnigmaSDK\VC\decrypt_on_execute_begin.inc"
    printf("Hello aaa\n");
// END 1
#include "J:\packers\enigma\enigma3.10\EnigmaSDK\VC\decrypt_on_execute_end.inc"

// BEGIN 2
#include "J:\packers\enigma\enigma3.10\EnigmaSDK\VC\vm_begin.inc"
    printf("Hello bbb\n");
// END 2
#include "J:\packers\enigma\enigma3.10\EnigmaSDK\VC\vm_end.inc"

    return 0;
}