#include <stdio.h>
#include "windows.h"

// INCLUDE
#include "J:\packers\Themida\ThemidaV304\ThemidaSDK\Include\C\ThemidaSDK.h"


// DEFINE

int main()
{
// BEGIN 1
VM_FISH_WHITE_START
    HMODULE handle = GetModuleHandle(NULL);
// END 1
VM_FISH_WHITE_END

// BEGIN 2
    printf("%p\n", handle);
// END 2

    return 0;
}