#include <stdio.h>
 
 int main(int argc, const char *argv[])
{
    int s[10] = {23,45,65,78,90,55,33,17,96,54};
    int i = 0;
    int j = 0;
    int temp = 0;
    int flags=0;
    int len = sizeof(s)/sizeof(int);
 
    for(i = 0; i < len; i++){
    printf("%d ", s[i]);
    }
 
    printf("\n");
 
    for(j = 0; j < len-1; j++){
        flags=0;
        for(i = 0; i < len-1-j; i++){
            if(s[i] > s[i+1]){
                temp = s[i];
                s[i] = s[i+1];
                s[i+1] = temp;
                flags=1;
            }
        }
        if(flags==0){
             break;
         }        
    }
 
    for(i = 0; i < len; i++){
        printf("%d ", s[i]);
    }
 
    printf("\n");
 
    return 0;
 }