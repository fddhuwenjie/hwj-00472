#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

typedef int (*math_fn_t)(int, int);

int static_add(int a, int b) {
    return a + b;
}

int main(int argc, char *argv[]) {
    void *handle;
    math_fn_t dyn_add;
    char *error;
    int a = 15, b = 27;

    printf("Static linking test: %d + %d = %d\n", a, b, static_add(a, b));

    handle = dlopen("libm.so.6", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        handle = dlopen("/lib/x86_64-linux-gnu/libm.so.6", RTLD_NOW);
    }

    if (handle) {
        printf("Dynamic linking: libm loaded successfully\n");
        dlclose(handle);
    } else {
        printf("Dynamic linking note: libm not loaded (macOS/linux difference)\n");
    }

    char *buf = (char *)malloc(128);
    snprintf(buf, 128, "Dynamic string test: argc=%d", argc);
    printf("%s\n", buf);
    free(buf);

    return 0;
}
