#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "windows.h"

// INCLUDE
#include "J:\packers\Themida\ThemidaV237\ThemidaSDK\Include\C\ThemidaSDK.h"


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
VM_FISH_WHITE_START
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
VM_FISH_WHITE_END

// BEGIN 2
ENCODE_START
    for(int i=0; i<10; i++)
    {
        printf("%d ", arr[i]);
    }
    printf("\n");
// END 2
ENCODE_END

    return 0;
}