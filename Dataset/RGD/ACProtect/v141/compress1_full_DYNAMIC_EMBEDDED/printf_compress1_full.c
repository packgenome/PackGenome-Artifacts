#include <stdio.h>

#include "windows.h"
// INCLUDE
#include "J:\packers\ACProtect\ACProtect_v141\example\vc\include\ACProtect.h"


// DEFINE


int main(void)
{

// BEGIN 1
DYNAMIC_BEGIN
    printf("Hello aaa\n");
// END 1
DYNAMIC_END

// BEGIN 2
EMBEDDED_BEGIN
    printf("Hello bbb\n");
// END 2
EMBEDDED_END

    return 0;
}