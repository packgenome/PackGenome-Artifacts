#include <stdio.h>
 
 int main(int argc, const char *argv[])
 {
    int i = 0;
    int j = 0;
    int sum = 0;
 
    for(i = 1; i < 1000; i++){
        sum = 0;
        for(j = 1; j < i; j++){
            if(i%j == 0){       
                sum += j;
            }
        }       
        if(sum == i){
            printf("%d\n", i);
        }
    }
 return 0;
 }