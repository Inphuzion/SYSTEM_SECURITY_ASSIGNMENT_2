#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sodium.h>

/* ---------- helper functions (above main) ---------- */

static int hexval(char c) {
   static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';        // '0'..'9' → 0..9
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;   // 'a' → 10, 'f' → 15
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;   // same for capitals
    return -1;                                       // not a hex digit
}
}

int parse_scalar(const char *hex, unsigned char out[32]) {
    // TODO 1: skip "0x"/"0X"
    size_t len = strlen(hex);
    // TODO 2: check len

    memset(out, 0, 32);
    for (size_t j = 0; j < len; j++) {
        char c = hex[len - 1 - j];
        int v = hexval(c);
        // TODO 3
        // TODO 4
    }
    return 0;
}

/* ---------- main (always last) ---------- */

int main(void) {
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }

    // temporary test, we'll delete it later
    unsigned char s[32];
    const char *tests[] = { "0x1a2b3c", "0x1a2b3", "0x2022123456", "ff", "0xzz", "" };
    for (int t = 0; t < 6; t++) {
        int r = parse_scalar(tests[t], s);
        printf("%-14s r=%2d  ", tests[t], r);
        if (r == 0) for (int i = 0; i < 6; i++) printf("%02x ", s[i]);
        printf("\n");
    }
    return 0;
}