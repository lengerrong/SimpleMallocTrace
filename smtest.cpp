#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

class A {
};

int main()
{
    int* a, *b, *c;
    A* aa;
    printf("begin\n");
    a = (int*)malloc(100);
    b = (int*)malloc(1024);
    c = (int*)malloc(2000);
    aa = new A();
    printf("done\n");
    free(a);
    free(b);
    free(c);
    delete aa;
    return 0;
}
