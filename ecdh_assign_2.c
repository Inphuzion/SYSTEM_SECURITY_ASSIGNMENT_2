#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int parse_scalar(const char *hex, unsigned char out[32]) {
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        hex += 2;
    size_t len = strlen(hex);
    if (len == 0 || len > 64)
        return -1;
    memset(out, 0, 32);
    for (size_t j = 0; j < len; j++) {
        int v = hexval(hex[len - 1 - j]);
        if (v < 0)
            return -1;
        if (j % 2 == 0) out[j / 2] |= v;
        else            out[j / 2] |= v << 4;
    }
    return 0;
}


static void print_hex(FILE *f, const char *label, const unsigned char *buf, size_t n) {
    fprintf(f, "%s: ", label);
    for (size_t i = 0; i < n; i++)
        fprintf(f, "%02x", buf[i]);
    fprintf(f, "\n");
}

static void usage(void) {
    printf("Usage: ./ecdh_assign_2 -o path -n AM [-a hex] [-b hex] [-h]\n"
           "  -o path  output file (required)\n"
           "  -n AM    student number, KDF context (required)\n"
           "  -a hex   Alice's private key (optional)\n"
           "  -b hex   Bob's private key (optional)\n"
           "  -h       this help message\n");
}


int main(int argc, char *argv[]) {
    const char *out_path = NULL, *am = NULL, *a_hex = NULL, *b_hex = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "o:n:a:b:h")) != -1) {
        switch (opt) {
            case 'o': out_path = optarg; break;
            case 'n': am = optarg; break;
            case 'a': a_hex = optarg; break;
            case 'b': b_hex = optarg; break;
            case 'h': usage(); return 0;
            default:  usage(); return 1;
        }
    }
    if (!out_path || !am) { usage(); return 1; }
    if (strlen(am) < 8) { fprintf(stderr, "AM must have at least 8 digits\n"); return 1; }

    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }



        unsigned char a[32], b[32];
    if (a_hex) { if (parse_scalar(a_hex, a) != 0) { fprintf(stderr, "Invalid -a\n"); return 1; } }
    else randombytes_buf(a, 32);
    if (b_hex) { if (parse_scalar(b_hex, b) != 0) { fprintf(stderr, "Invalid -b\n"); return 1; } }
    else randombytes_buf(b, 32);


        unsigned char A[32], B[32];
    if (crypto_scalarmult_base(A, a) != 0 || crypto_scalarmult_base(B, b) != 0) {
        fprintf(stderr, "Public key computation failed\n"); return 1;
    }

    unsigned char SA[32], SB[32];
    if (crypto_scalarmult(SA, a, B) != 0 || crypto_scalarmult(SB, b, A) != 0) {
        fprintf(stderr, "Shared secret computation failed\n"); return 1;
    }
    int match = sodium_memcmp(SA, SB, 32) == 0;

        unsigned char buf[96];
    memcpy(buf, SA, 32);
    memcpy(buf + 32, A, 32);
    memcpy(buf + 64, B, 32);
    unsigned char master[32];
    crypto_generichash(master, 32, buf, sizeof buf, NULL, 0);



        char ctx[crypto_kdf_CONTEXTBYTES];
    memcpy(ctx, am + strlen(am) - 8, 8);
    unsigned char enc_key[32], mac_key[32];
    crypto_kdf_derive_from_key(enc_key, 32, 1, ctx, master);
    crypto_kdf_derive_from_key(mac_key, 32, 2, ctx, master);


        FILE *f = fopen(out_path, "w");
    if (!f) { perror(out_path); return 1; }
    fprintf(f, "AM: %s\n", am);
    print_hex(f, "Alice Public Key", A, 32);
    print_hex(f, "Bob Public Key", B, 32);
    print_hex(f, "Shared Secret (Alice)", SA, 32);
    print_hex(f, "Shared Secret (Bob)", SB, 32);
    fprintf(f, "%s\n", match ? "Shared secrets match!" : "Shared secrets DO NOT match!");
    print_hex(f, "Master Key", master, 32);
    print_hex(f, "Encryption Key", enc_key, 32);
    print_hex(f, "MAC Key", mac_key, 32);
    fclose(f);

    sodium_memzero(a, 32); sodium_memzero(b, 32);
    return 0;
}