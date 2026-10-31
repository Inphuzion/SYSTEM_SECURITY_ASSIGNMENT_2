#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <gmp.h>
#include <sodium.h>

#define MARK_ENC 0x3A
#define MARK_SIG 0x5A

typedef struct {
    int bits;            /* key length from the header, e.g. 2048 */
    int is_private;      /* 0 = public key file, 1 = private key file */
    mpz_t n, e, d, p, q;
} rsa_key;

static void key_init(rsa_key *k) {
    mpz_inits(k->n, k->e, k->d, k->p, k->q, NULL);
    k->bits = 0;
    k->is_private = 0;
}

static void key_clear(rsa_key *k) {
    mpz_clears(k->n, k->e, k->d, k->p, k->q, NULL);
}

/* Reads one line "label: hex" into x. Returns 0 on success. */
static int read_field(FILE *f, const char *label, mpz_t x) {
    char name[16];
    char hex[4200];
    if (fscanf(f, "%15[^:]: %4199s ", name, hex) != 2) return -1;
    if (strcmp(name, label) != 0) return -1;
    return mpz_set_str(x, hex, 16);
}

static int load_key(const char *path, rsa_key *k) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }

    char type[32];
    if (fscanf(f, "%31s %d ", type, &k->bits) != 2) goto bad;

    if (strcmp(type, "RSA-PUBLIC-KEY") == 0) {
        k->is_private = 0;
        if (read_field(f, "n", k->n) || read_field(f, "e", k->e)) goto bad;
    } else if (strcmp(type, "RSA-PRIVATE-KEY") == 0) {
        k->is_private = 1;
        if (read_field(f, "n", k->n) || read_field(f, "d", k->d) ||
            read_field(f, "p", k->p) || read_field(f, "q", k->q)) goto bad;
        mpz_set_ui(k->e, 65537);
    } else goto bad;
    fclose(f);

    if (k->bits <= 0 || k->bits % 8 != 0 || (int)mpz_sizeinbase(k->n, 2) != k->bits) {
        fprintf(stderr, "%s: n does not have %d bits\n", path, k->bits);
        return -1;
    }
    if (k->is_private) {
        mpz_t pq; mpz_init(pq);
        mpz_mul(pq, k->p, k->q);
        int ok = mpz_cmp(pq, k->n) == 0;
        mpz_clear(pq);
        if (!ok) { fprintf(stderr, "%s: p*q != n\n", path); return -1; }
    }
    return 0;
bad:
    fclose(f);
    fprintf(stderr, "%s: malformed key file\n", path);
    return -1;
}


static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(sz > 0 ? sz : 1);
    if (sz > 0 && fread(buf, 1, sz, f) != (size_t)sz) { fclose(f); free(buf); return NULL; }
    fclose(f);
    *len = sz;
    return buf;
}


/* Builds a k-byte frame: 00 | marker | len (2 bytes BE) | chunk | FF..FF */
static void make_frame(unsigned char *frame, size_t k, unsigned char marker,
                       const unsigned char *chunk, size_t len) {
    frame[0] = 0x00;
    frame[1] = marker;
    frame[2] = (len >> 8) & 0xFF;   /* high byte of the length */
    frame[3] = len & 0xFF;          /* low byte */
    memcpy(frame + 4, chunk, len);
    memset(frame + 4 + len, 0xFF, k - 4 - len);
}

/* Checks a frame. On success returns the chunk length, on failure -1. */
static long check_frame(const unsigned char *frame, size_t k, unsigned char marker) {
    if (frame[0] != 0x00 || frame[1] != marker) return -1;
    size_t len = ((size_t)frame[2] << 8) | frame[3];
    if (len > k - 4) return -1;
    for (size_t i = 4 + len; i < k; i++)
        if (frame[i] != 0xFF) return -1;
    return (long)len;
}

/* mpz -> exactly k bytes, big-endian, left-padded with zeros */
static void mpz_to_bytes(unsigned char *out, size_t k, const mpz_t x) {
    size_t count = 0;
    memset(out, 0, k);
    size_t need = (mpz_sizeinbase(x, 2) + 7) / 8;
    if (mpz_sgn(x) == 0) return;
    mpz_export(out + (k - need), &count, 1, 1, 1, 0, x);
}


static void rsa_public(mpz_t out, const mpz_t m, const rsa_key *k) {
    mpz_powm(out, m, k->e, k->n);
}

/* Plain: m = c^d mod n */
static void rsa_private(mpz_t out, const mpz_t c, const rsa_key *k) {
    mpz_powm(out, c, k->d, k->n);
}

/* CRT: two half-size exponentiations instead of one full-size one */
static void rsa_private_crt(mpz_t m, const mpz_t c, const rsa_key *k) {
    mpz_t dp, dq, qinv, mp, mq, h, t;
    mpz_inits(dp, dq, qinv, mp, mq, h, t, NULL);

    mpz_sub_ui(t, k->p, 1); mpz_mod(dp, k->d, t);   /* d_p = d mod (p-1) */
    mpz_sub_ui(t, k->q, 1); mpz_mod(dq, k->d, t);   /* d_q = d mod (q-1) */
    mpz_invert(qinv, k->q, k->p);                   /* q_inv = q^-1 mod p */

    mpz_powm(mp, c, dp, k->p);                      /* m_p = c^d_p mod p */
    mpz_powm(mq, c, dq, k->q);                      /* m_q = c^d_q mod q */

    mpz_sub(h, mp, mq);                             /* h = q_inv*(m_p-m_q) mod p */
    mpz_mul(h, h, qinv);
    mpz_mod(h, h, k->p);                            /* mpz_mod always gives >= 0 */

    mpz_mul(m, h, k->q);                            /* m = m_q + h*q */
    mpz_add(m, m, mq);

    mpz_clears(dp, dq, qinv, mp, mq, h, t, NULL);
}


static unsigned char *encrypt_buf(const unsigned char *in, size_t len, const rsa_key *key,
                                  size_t *out_len) {
    size_t k = key->bits / 8, L = k - 4;
    size_t nblocks = (len + L - 1) / L;          /* ceil(len / L); 0 if the file is empty */
    unsigned char *out = malloc(nblocks * k + 1);
    unsigned char *frame = malloc(k);
    mpz_t m, c; mpz_inits(m, c, NULL);

    for (size_t i = 0; i < nblocks; i++) {
        size_t off = i * L;
        size_t clen = (len - off < L) ? len - off : L;   /* the last chunk may be shorter */
        make_frame(frame, k, MARK_ENC, in + off, clen);
        mpz_import(m, k, 1, 1, 1, 0, frame);           /* bytes -> integer, big-endian */
        rsa_public(c, m, key);
        mpz_to_bytes(out + i * k, k, c);                /* integer -> exactly k bytes */
    }
    mpz_clears(m, c, NULL);
    free(frame);
    *out_len = nblocks * k;
    return out;
}

static unsigned char *decrypt_buf(const unsigned char *in, size_t len, const rsa_key *key,
                                  int use_crt, size_t *out_len) {
    size_t k = key->bits / 8;
    if (len % k != 0) {
        fprintf(stderr, "Ciphertext size %zu is not a multiple of %zu\n", len, k);
        return NULL;
    }
    size_t nblocks = len / k;
    unsigned char *out = malloc(len + 1);
    unsigned char *frame = malloc(k);
    size_t pos = 0;
    mpz_t m, c; mpz_inits(m, c, NULL);

    for (size_t i = 0; i < nblocks; i++) {
        mpz_import(c, k, 1, 1, 1, 0, in + i * k);
        if (use_crt) rsa_private_crt(m, c, key);
        else         rsa_private(m, c, key);
        mpz_to_bytes(frame, k, m);                      /* left-padding matters here */
        long clen = check_frame(frame, k, MARK_ENC);
        if (clen < 0) {
            fprintf(stderr, "Malformed frame in block %zu\n", i);
            mpz_clears(m, c, NULL); free(frame); free(out);
            return NULL;
        }
        memcpy(out + pos, frame + 4, clen);             /* keep only the chunk, drop the FF padding */
        pos += clen;
    }
    mpz_clears(m, c, NULL);
    free(frame);
    *out_len = pos;
    return out;
}


/* Computes the signature s of in[0..len). Also returns the hash h. */
static void sign_buf(mpz_t s, unsigned char h[32], const unsigned char *in, size_t len,
                     const rsa_key *key) {
    size_t k = key->bits / 8;
    unsigned char *frame = malloc(k);
    mpz_t m; mpz_init(m);
    crypto_hash_sha256(h, in, len);                 /* h = SHA-256(file) */
    make_frame(frame, k, MARK_SIG, h, 32);          /* same framing, marker 0x5A */
    mpz_import(m, k, 1, 1, 1, 0, frame);
    rsa_private(s, m, key);                         /* s = m^d mod n */
    mpz_clear(m);
    free(frame);
}

/* Returns 1 if valid. When invalid, prints to stderr which check failed. */
static int verify_buf(const unsigned char *in, size_t len, int sig_bits,
                      const char *sig_hash_hex, const mpz_t s, const rsa_key *key) {
    size_t k = key->bits / 8;
    unsigned char h[32];
    char h_hex[65];
    crypto_hash_sha256(h, in, len);
    sodium_bin2hex(h_hex, sizeof h_hex, h, 32);

    if (sig_bits != key->bits) {
        fprintf(stderr, "check 1 failed: key length in signature (%d) != key (%d)\n",
                sig_bits, key->bits);
        return 0;
    }
    if (strcmp(sig_hash_hex, h_hex) != 0) {
        fprintf(stderr, "check 2 failed: sha256 line does not match the file\n");
        return 0;
    }
    if (mpz_cmp(s, key->n) >= 0) {
        fprintf(stderr, "check 3 failed: s >= n\n");
        return 0;
    }
    unsigned char *frame = malloc(k);
    mpz_t m; mpz_init(m);
    rsa_public(m, s, key);                          /* s^e mod n */
    mpz_to_bytes(frame, k, m);
    long flen = check_frame(frame, k, MARK_SIG);
    int ok = 1;
    if (flen != 32) {
        fprintf(stderr, "check 4 failed: s^e mod n is not a valid 0x5A frame of length 32\n");
        ok = 0;
    } else if (memcmp(frame + 4, h, 32) != 0) {
        fprintf(stderr, "check 5 failed: hash inside the frame != SHA-256 of the file\n");
        ok = 0;
    }
    mpz_clear(m);
    free(frame);
    return ok;
}



int main(int argc, char *argv[]) {
        const char *in_path = NULL, *out_path = NULL, *key_path = NULL, *sig_path = NULL;
    int opt, mode = 0, use_crt = 0;
        while ((opt = getopt(argc, argv, "i:o:k:edcsv:")) != -1) { 
        switch (opt) {
            case 'i': in_path = optarg; break;
            case 'o': out_path = optarg; break;
            case 'k': key_path = optarg; break;
            case 'e': mode = 'e'; break;
            case 'd': mode = 'd'; break;
            case 'c': use_crt = 1; break;
            case 's': mode = 's'; break;
            case 'v': mode = 'v'; sig_path = optarg; break;
            default: return 1;
        }
    }
     if (!mode || !in_path || !key_path || (mode != 'v' && !out_path)) { fprintf(stderr, "missing arguments\n"); return 1; }

    rsa_key key; key_init(&key);
    if (load_key(key_path, &key)) return 1;

    size_t len, out_len;
    unsigned char *in = read_file(in_path, &len);
    if (!in) return 1;
    if (mode == 's') {
        mpz_t s; mpz_init(s);
        unsigned char h[32];
        char h_hex[65];
        sign_buf(s, h, in, len, &key);
        sodium_bin2hex(h_hex, sizeof h_hex, h, 32);
        FILE *f = fopen(out_path, "w");
        gmp_fprintf(f, "RSA-SIGNATURE %d\nsha256: %s\ns: %Zx\n", key.bits, h_hex, s);
        fclose(f);
        return 0;
    }
    if (mode == 'v') {
        FILE *f = fopen(sig_path, "r");
        if (!f) { perror(sig_path); return 1; }
        int sig_bits = 0;
        char hash_hex[128] = "", s_hex[4200] = "";
        mpz_t s; mpz_init(s);
        int parsed = fscanf(f, "RSA-SIGNATURE %d sha256: %127s s: %4199s", &sig_bits, hash_hex, s_hex) == 3
                     && mpz_set_str(s, s_hex, 16) == 0;
        fclose(f);
        if (parsed && verify_buf(in, len, sig_bits, hash_hex, s, &key)) {
            printf("Signature is VALID\n");
            return 0;
        }
        if (!parsed) fprintf(stderr, "malformed signature file\n");
        printf("Signature is INVALID\n");
        return 2;
    }



    unsigned char *out = (mode == 'e') ? encrypt_buf(in, len, &key, &out_len)
                                       : decrypt_buf(in, len, &key, use_crt, &out_len);
    if (!out) return 1;

    FILE *f = fopen(out_path, "wb");
    fwrite(out, 1, out_len, f);
    fclose(f);
    printf("%zu bytes in, %zu blocks, %zu bytes out\n", len, len / (key.bits / 8), out_len);
    return 0;
}