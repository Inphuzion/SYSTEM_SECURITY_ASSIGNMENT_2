#include <stdio.h>
#include <sodium.h>

int main(void) {
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }
    printf("libsodium %s OK\n", sodium_version_string());
    return 0;
}