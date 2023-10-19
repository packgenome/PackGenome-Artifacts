#include <stdio.h>
#include "windows.h"

// INCLUDE
#include "J:\packers\ACProtect\ACProtect_v141\example\vc\include\ACProtect.h"


// DEFINE

int main()
{
// BEGIN 1
DYNAMIC_BEGIN
    HMODULE handle = GetModuleHandle(NULL);
// END 1
DYNAMIC_END

// BEGIN 2
EMBEDDED_BEGIN
    printf("%p\n", handle);
// END 2
EMBEDDED_END

    return 0;
}