#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void revertPrint(char *p){
    if (*p == '\0') {
        return;
    }
    revertPrint(p+1);
    printf("%c",*p);
}


int main(void){
    char *s = "abcd";
    revertPrint(s);
}