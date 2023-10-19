#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void sortArray(char **str,int len){
    for (int i = 0; i<len; i++) {
        for (int j=i+1; j<len; j++) {
            if (*str[i] > *str[j] ) {
                char *temp = str[i];
                str[i] = str[j];
                str[j] = temp;
            }
        }
    }
};
int main(int argc, const char * argv[]) {
    char *str1[] = {"asd","sdf","dfg","ghj","qscx"};
    int len = sizeof(str1)/sizeof(char *);
    sortArray(str1,len);
    for (int i = 0; i<len; i++) {
        printf("%s\n",str1[i]);
    }
    return 0;
}