#include <stdio.h>
#include "windows.h"

// INCLUDE
#include "J:\packers\ACProtect\ACProtect_v141\example\vc\include\ACProtect.h"


// DEFINE

int main()
{
// BEGIN 1
    HMODULE handle = GetModuleHandle(NULL);
// END 1

// BEGIN 2
    printf("%p\n", handle);
// END 2

    return 0;
}