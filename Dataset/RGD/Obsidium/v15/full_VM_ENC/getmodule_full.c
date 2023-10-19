#include <stdio.h>
#include "windows.h"

// INCLUDE
#include "J:\packers\obsidium\obsidium_v15\SDK\C\API\obsidium.h"


// DEFINE

int main()
{
// BEGIN 1
OBSIDIUM_VM_START
    HMODULE handle = GetModuleHandle(NULL);
// END 1
OBSIDIUM_VM_END

// BEGIN 2
OBSIDIUM_ENC_START
    printf("%p\n", handle);
// END 2
OBSIDIUM_ENC_END

    return 0;
}