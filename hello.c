#include <stdio.h>

int global_var = 42;
const char *msg = "Hello, ELF World!";

static int add(int a, int b) {
    return a + b;
}

int main() {
    int x = 10;
    int y = 20;
    int result = add(x, y);
    printf("%s result=%d global=%d\n", msg, result, global_var);
    return 0;
}
