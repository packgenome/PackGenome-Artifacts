#include <stdio.h>

int strLen(char s[]);

int main()
{
    char string[] = "hello, world";
    printf("%d\n", strLen(string));
}

int strLen(char s[])
{
    int i;

    while (s[i] != '\0') {
        ++i;
    }

    return i;
}