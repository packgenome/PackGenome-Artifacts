#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "windows.h"

// INCLUDE


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
#include "J:\packers\enigma\enigma1.55\EnigmaSDK\VC\decrypt_on_execute_begin.inc"
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
#include "J:\packers\enigma\enigma1.55\EnigmaSDK\VC\decrypt_on_execute_end.inc"

// BEGIN 2
    for(int i=0; i<10; i++)
    {
        printf("%d ", arr[i]);
    }
    printf("\n");
// END 2

    return 0;
}