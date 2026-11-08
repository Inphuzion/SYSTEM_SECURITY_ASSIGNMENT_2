#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <gmp.h>
#include <sodium.h>

#define MARK_ENC 0x3A
#define MARK_SIG 0x5A

/*  Part A: key structure and files  */

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

    /* checks required by the assignment */
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

static int save_key(const char *path, const rsa_key *k) {
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return -1; }
    if (k->is_private) {
        gmp_fprintf(f, "RSA-PRIVATE-KEY %d\nn: %Zx\nd: %Zx\np: %Zx\nq: %Zx\n",
                    k->bits, k->n, k->d, k->p, k->q);
    } else {
        gmp_fprintf(f, "RSA-PUBLIC-KEY %d\nn: %Zx\ne: %Zx\n", k->bits, k->n, k->e);
    }
    fclose(f);
    return 0;
}

/*  Part B: small file helpers*/

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

/* Part C: framing and byte conversion  */

/* Builds a k-byte frame: 00 | marker | len (2 bytes BE) | chunk | FF..FF */
static void make_frame(unsigned char *frame, size_t k, unsigned char marker,
                       const unsigned char *chunk, size_t len) {
    frame[0] = 0x00;
    frame[1] = marker;
    frame[2] = (len >> 8) & 0xFF;
    frame[3] = len & 0xFF;
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

/*  Part D: RSA core */

static void rsa_public(mpz_t out, const mpz_t m, const rsa_key *k) {
    mpz_powm(out, m, k->e, k->n);
}

static void rsa_private(mpz_t out, const mpz_t c, const rsa_key *k) {
    mpz_powm(out, c, k->d, k->n);
}

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
    mpz_mod(h, h, k->p);                            /* mpz_mod is always >= 0 */

    mpz_mul(m, h, k->q);                            /* m = m_q + h*q */
    mpz_add(m, m, mq);

    mpz_clears(dp, dq, qinv, mp, mq, h, t, NULL);
}

/*  Part E: operations on buffers  */

/* Encrypts in[0..len) into a newly allocated buffer of nblocks*k bytes. */
static unsigned char *encrypt_buf(const unsigned char *in, size_t len, const rsa_key *key,
                                  size_t *out_len) {
    size_t k = key->bits / 8, L = k - 4;
    size_t nblocks = (len + L - 1) / L;
    unsigned char *out = malloc(nblocks * k + 1);
    unsigned char *frame = malloc(k);
    mpz_t m, c; mpz_inits(m, c, NULL);

    for (size_t i = 0; i < nblocks; i++) {
        size_t off = i * L;
        size_t clen = (len - off < L) ? len - off : L;
        make_frame(frame, k, MARK_ENC, in + off, clen);
        mpz_import(m, k, 1, 1, 1, 0, frame);
        rsa_public(c, m, key);
        mpz_to_bytes(out + i * k, k, c);
    }
    mpz_clears(m, c, NULL);
    free(frame);
    *out_len = nblocks * k;
    return out;
}

/* Decrypts; returns NULL on error (message already printed). */
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
        mpz_to_bytes(frame, k, m);
        long clen = check_frame(frame, k, MARK_ENC);
        if (clen < 0) {
            fprintf(stderr, "Malformed frame in block %zu\n", i);
            mpz_clears(m, c, NULL); free(frame); free(out);
            return NULL;
        }
        memcpy(out + pos, frame + 4, clen);
        pos += clen;
    }
    mpz_clears(m, c, NULL);
    free(frame);
    *out_len = pos;
    return out;
}

/* Computes s for the signature of in[0..len). */
static void sign_buf(mpz_t s, unsigned char h[32], const unsigned char *in, size_t len,
                     const rsa_key *key) {
    size_t k = key->bits / 8;
    unsigned char *frame = malloc(k);
    mpz_t m; mpz_init(m);
    crypto_hash_sha256(h, in, len);
    make_frame(frame, k, MARK_SIG, h, 32);
    mpz_import(m, k, 1, 1, 1, 0, frame);
    rsa_private(s, m, key);
    mpz_clear(m);
    free(frame);
}

/* Returns 1 if valid. Prints which check failed (to stderr) when invalid. */
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
    rsa_public(m, s, key);
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

/*  Part F: key generation  */

static gmp_randstate_t rstate;

static void random_prime(mpz_t p, int bits) {
    do {
        mpz_urandomb(p, rstate, bits);
        mpz_setbit(p, bits - 1);   /* exactly `bits` bits */
        mpz_setbit(p, bits - 2);   /* so that p*q has exactly 2*bits bits */
        mpz_setbit(p, 0);          /* odd */
    } while (mpz_probab_prime_p(p, 30) == 0);
}

static void generate_key(rsa_key *pub, rsa_key *priv, int bits) {
    mpz_t lambda, t;
    mpz_inits(lambda, t, NULL);
    for (;;) {
        random_prime(priv->p, bits / 2);
        do random_prime(priv->q, bits / 2); while (mpz_cmp(priv->p, priv->q) == 0);
        mpz_mul(priv->n, priv->p, priv->q);
        if ((int)mpz_sizeinbase(priv->n, 2) != bits) continue;

        mpz_sub_ui(lambda, priv->p, 1);
        mpz_sub_ui(t, priv->q, 1);
        mpz_mul(lambda, lambda, t);                 /* lambda = (p-1)(q-1) */

        mpz_set_ui(priv->e, 65537);
        mpz_gcd(t, priv->e, lambda);
        if (mpz_cmp_ui(t, 1) != 0) continue;        /* gcd != 1 -> new primes */

        mpz_invert(priv->d, priv->e, lambda);
        break;
    }
    priv->bits = pub->bits = bits;
    priv->is_private = 1;
    pub->is_private = 0;
    mpz_set(pub->n, priv->n);
    mpz_set(pub->e, priv->e);
    mpz_clears(lambda, t, NULL);
}

/* Part G: performance analysis  */

static size_t mem_current = 0, mem_peak = 0;

static void *track_alloc(size_t n) {
    mem_current += n;
    if (mem_current > mem_peak) mem_peak = mem_current;
    return malloc(n);
}
static void *track_realloc(void *ptr, size_t old_n, size_t new_n) {
    mem_current = mem_current - old_n + new_n;
    if (mem_current > mem_peak) mem_peak = mem_current;
    return realloc(ptr, new_n);
}
static void track_free(void *ptr, size_t n) {
    mem_current -= n;
    free(ptr);
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int performance(const char *in_path, const char *out_path) {
    size_t len;
    unsigned char *in = read_file(in_path, &len);
    if (!in) return 1;
    FILE *f = fopen(out_path, "w");
    if (!f) { perror(out_path); free(in); return 1; }

    mp_set_memory_functions(track_alloc, track_realloc, track_free);

    int sizes[3] = {1024, 2048, 4096};
    for (int i = 0; i < 3; i++) {
        rsa_key pub, priv;
        key_init(&pub); key_init(&priv);
        generate_key(&pub, &priv, sizes[i]);

        size_t clen, plen, plen2;
        unsigned char *ct, *pt, *pt2, h[32];
        char h_hex[65];
        mpz_t s; mpz_init(s);
        double t0, t_enc, t_dec, t_crt, t_sig, t_ver;
        size_t m_enc, m_dec, m_crt, m_sig, m_ver;

        mem_peak = mem_current; t0 = now();
        ct = encrypt_buf(in, len, &pub, &clen);
        t_enc = now() - t0; m_enc = mem_peak;

        mem_peak = mem_current; t0 = now();
        pt = decrypt_buf(ct, clen, &priv, 0, &plen);
        t_dec = now() - t0; m_dec = mem_peak;

        mem_peak = mem_current; t0 = now();
        pt2 = decrypt_buf(ct, clen, &priv, 1, &plen2);
        t_crt = now() - t0; m_crt = mem_peak;

        if (!pt || !pt2 || plen != len || plen2 != len ||
            memcmp(pt, in, len) || memcmp(pt2, in, len))
            fprintf(stderr, "Warning: round trip failed for %d bits\n", sizes[i]);

        mem_peak = mem_current; t0 = now();
        sign_buf(s, h, in, len, &priv);
        t_sig = now() - t0; m_sig = mem_peak;

        sodium_bin2hex(h_hex, sizeof h_hex, h, 32);
        mem_peak = mem_current; t0 = now();
        int ok = verify_buf(in, len, sizes[i], h_hex, s, &pub);
        t_ver = now() - t0; m_ver = mem_peak;
        if (!ok) fprintf(stderr, "Warning: verification failed for %d bits\n", sizes[i]);

        fprintf(f, "Key Length: %d bits\n", sizes[i]);
        fprintf(f, "Encryption Time: %.4fs\n", t_enc);
        fprintf(f, "Decryption Time: %.4fs\n", t_dec);
        fprintf(f, "Decryption Time (CRT): %.4fs\n", t_crt);
        fprintf(f, "Signing Time: %.4fs\n", t_sig);
        fprintf(f, "Verification Time: %.4fs\n", t_ver);
        fprintf(f, "Peak Memory Usage (Encryption): %zu bytes\n", m_enc);
        fprintf(f, "Peak Memory Usage (Decryption): %zu bytes\n", m_dec);
        fprintf(f, "Peak Memory Usage (Decryption, CRT): %zu bytes\n", m_crt);
        fprintf(f, "Peak Memory Usage (Signing): %zu bytes\n", m_sig);
        fprintf(f, "Peak Memory Usage (Verification): %zu bytes\n", m_ver);
        if (i < 2) fprintf(f, "\n");

        free(ct); free(pt); free(pt2);
        mpz_clear(s);
        key_clear(&pub); key_clear(&priv);
    }
    fclose(f);
    free(in);
    return 0;
}

/*  Part H: main  */

static void usage(void) {
    printf("Usage:\n"
           "  ./rsa_assign_2 -g length                       generate key pair (1024, 2048, 4096)\n"
           "  ./rsa_assign_2 -i in -o out -k pub.key -e      encrypt\n"
           "  ./rsa_assign_2 -i in -o out -k priv.key -d     decrypt\n"
           "  ./rsa_assign_2 -i in -o out -k priv.key -s     sign\n"
           "  ./rsa_assign_2 -i in -k pub.key -v sigfile     verify\n"
           "  ./rsa_assign_2 -a perf.txt -i in               performance analysis\n"
           "  ./rsa_assign_2 -h                              this help message\n");
}

int main(int argc, char *argv[]) {
    const char *in_path = NULL, *out_path = NULL, *key_path = NULL;
    const char *sig_path = NULL, *perf_path = NULL;
    int gen_bits = 0;
    char mode = 0;   /* 'g', 'e', 'd', 's', 'v', 'a' */
    int nmodes = 0;
    int opt;

    while ((opt = getopt(argc, argv, "i:o:k:g:edsv:a:h")) != -1) {
        switch (opt) {
            case 'i': in_path = optarg; break;
            case 'o': out_path = optarg; break;
            case 'k': key_path = optarg; break;
            case 'g': mode = 'g'; nmodes++; gen_bits = atoi(optarg); break;
            case 'e': mode = 'e'; nmodes++; break;
            case 'd': mode = 'd'; nmodes++; break;
            case 's': mode = 's'; nmodes++; break;
            case 'v': mode = 'v'; nmodes++; sig_path = optarg; break;
            case 'a': mode = 'a'; nmodes++; perf_path = optarg; break;
            case 'h': usage(); return 0;
            default:  usage(); return 1;
        }
    }
    if (nmodes != 1) { usage(); return 1; }
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }

    /* seed GMP's random state with real randomness from libsodium */
    gmp_randinit_default(rstate);
    unsigned long seed;
    randombytes_buf(&seed, sizeof seed);
    gmp_randseed_ui(rstate, seed);

    if (mode == 'g') {
        if (gen_bits != 1024 && gen_bits != 2048 && gen_bits != 4096) {
            fprintf(stderr, "Key length must be 1024, 2048 or 4096\n"); return 1;
        }
        rsa_key pub, priv;
        key_init(&pub); key_init(&priv);
        generate_key(&pub, &priv, gen_bits);
        char name[64];
        snprintf(name, sizeof name, "public_%d.key", gen_bits);
        if (save_key(name, &pub)) return 1;
        snprintf(name, sizeof name, "private_%d.key", gen_bits);
        if (save_key(name, &priv)) return 1;
        key_clear(&pub); key_clear(&priv);
        return 0;
    }

    if (mode == 'a') {
        if (!in_path) { fprintf(stderr, "-a requires -i\n"); return 1; }
        return performance(in_path, perf_path);
    }

    /* e, d, s, v need -i and -k; e, d, s also need -o */
    if (!in_path || !key_path || (mode != 'v' && !out_path)) { usage(); return 1; }

    rsa_key key;
    key_init(&key);
    if (load_key(key_path, &key)) return 1;
    int need_private = (mode == 'd' || mode == 's');
    if (key.is_private != need_private) {
        fprintf(stderr, "This operation needs a %s key\n", need_private ? "private" : "public");
        return 1;
    }

    size_t len;
    unsigned char *in = read_file(in_path, &len);
    if (!in) return 1;
    int status = 0;

    if (mode == 'e' || mode == 'd') {
        size_t out_len;
        unsigned char *out = (mode == 'e') ? encrypt_buf(in, len, &key, &out_len)
                                           : decrypt_buf(in, len, &key, 1, &out_len);
        if (!out) return 1;
        FILE *f = fopen(out_path, "wb");
        if (!f) { perror(out_path); return 1; }
        fwrite(out, 1, out_len, f);
        fclose(f);
        free(out);
    } else if (mode == 's') {
        mpz_t s; mpz_init(s);
        unsigned char h[32];
        char h_hex[65];
        sign_buf(s, h, in, len, &key);
        sodium_bin2hex(h_hex, sizeof h_hex, h, 32);
        FILE *f = fopen(out_path, "w");
        if (!f) { perror(out_path); return 1; }
        gmp_fprintf(f, "RSA-SIGNATURE %d\nsha256: %s\ns: %Zx\n", key.bits, h_hex, s);
        fclose(f);
        mpz_clear(s);
    } else if (mode == 'v') {
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
        } else {
            if (!parsed) fprintf(stderr, "malformed signature file\n");
            printf("Signature is INVALID\n");
            status = 2;
        }
        mpz_clear(s);
    }

    free(in);
    key_clear(&key);
    return status;
}