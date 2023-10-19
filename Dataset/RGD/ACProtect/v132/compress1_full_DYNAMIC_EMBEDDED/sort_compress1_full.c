#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "windows.h"

// INCLUDE
#include "J:\packers\ACProtect\ACProtect_v141\example\vc\include\ACProtect.h"


// DEFINE

#define LEN 10

int arr[LEN];

int main(void)
{
    int temp;
    srand(time(NULL));
    for(int i=0; i<LEN; i++)
    {
        arr[i] = rand() % 10;
        printf("%d ", arr[i]);
    }
    printf("\n");

// BEGIN 1
DYNAMIC_BEGIN
    for(int i=0; i<LEN-1; i++)
    {
        for(int j=0; j<LEN-1-i; j++)
        {
            if(arr[j] > arr[j+1])
            {
                temp = arr[j];
                arr[j] = arr[j+1];
                arr[j+1] = temp;
            }
        }
    }
// END 1
DYNAMIC_END

// BEGIN 2
EMBEDDED_BEGIN
    for(int i=0; i<10; i++)
    {
        printf("%d ", arr[i]);
    }
    printf("\n");
// END 2
EMBEDDED_END

    return 0;
}