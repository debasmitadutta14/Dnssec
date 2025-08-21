/*
 * falcon2_.c - driver for Falcon-512 (logn = 9) using the Round-3 reference API.
 *
 * This expects the Round-3 reference sources (falcon.c, sign.c, keygen.c, fft.c, ...)
 * in the same directory and the corresponding headers (falcon.h, shake.h).
 */

#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "falcon.h"


#define LOGN 9   /* Falcon-512 */

static double elapsed_ms(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1000.0
         + (double)(b.tv_nsec - a.tv_nsec) / 1e6;
}

int main(void)
{
    unsigned logn = LOGN;
    int rc;

    /* sizes from macros */
    size_t priv_len = (size_t)FALCON_PRIVKEY_SIZE(logn);
    size_t pub_len  = (size_t)FALCON_PUBKEY_SIZE(logn);
    size_t sig_max  = (size_t)FALCON_SIG_COMPRESSED_MAXSIZE(logn);

    size_t tmpkg_len = (size_t)FALCON_TMPSIZE_KEYGEN(logn);
    size_t tmpsd_len = (size_t)FALCON_TMPSIZE_SIGNDYN(logn);
    size_t tmpvv_len = (size_t)FALCON_TMPSIZE_VERIFY(logn);

    printf("Using Falcon logn=%u (n=%u)\n", logn, 1u << logn);
    printf("Macro sizes: priv=%zu pub=%zu sig_max=%zu\n",
           priv_len, pub_len, sig_max);
    printf("Tmp sizes: keygen=%zu sign_dyn=%zu verify=%zu\n",
           tmpkg_len, tmpsd_len, tmpvv_len);

    /* allocate buffers */
    uint8_t *priv = malloc(priv_len);
    uint8_t *pub  = malloc(pub_len);
    uint8_t *sig  = malloc(sig_max);
    uint8_t *tmpkg = malloc(tmpkg_len);
    uint8_t *tmpsd = malloc(tmpsd_len);
    uint8_t *tmpvv = malloc(tmpvv_len);

    if (!priv || !pub || !sig || !tmpkg || !tmpsd || !tmpvv) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    /* deterministic seed for reproducibility (use better seed in production) */
    shake256_context rng;
    const uint8_t seed[] = "falcon-driver-seed";
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed) - 1);

    struct timespec t0, t1;
    double keygen_ms, sign_ms, verify_ms;
    size_t sig_len = sig_max;

    /* ---------- Key generation ---------- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = falcon_keygen_make(&rng, logn,
                            priv, priv_len,
                            pub,  pub_len,
                            tmpkg, tmpkg_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    keygen_ms = elapsed_ms(t0, t1);

    printf("falcon_keygen_make returned %d\n", rc);
    if (rc != 0) {
        fprintf(stderr, "keygen failed (rc=%d)\n", rc);
        goto cleanup;
    }

    /* ---------- Signing ---------- */
    const char *message = "Hello Falcon-512!";
    size_t mlen = strlen(message);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = falcon_sign_dyn(&rng,
                         sig, &sig_len, FALCON_SIG_COMPRESSED,
                         priv, priv_len,
                         (const uint8_t *)message, mlen,
                         tmpsd, tmpsd_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    sign_ms = elapsed_ms(t0, t1);

    printf("falcon_sign_dyn returned %d (sig_len=%zu)\n", rc, sig_len);
    if (rc != 0) {
        fprintf(stderr, "sign failed (rc=%d)\n", rc);
        goto cleanup;
    }

    /* ---------- Verification ---------- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = falcon_verify(sig, sig_len, FALCON_SIG_COMPRESSED,
                       pub, pub_len,
                       (const uint8_t *)message, mlen,
                       tmpvv, tmpvv_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    verify_ms = elapsed_ms(t0, t1);

    printf("falcon_verify returned %d\n", rc);
    if (rc != 0) {
        fprintf(stderr, "verify failed (rc=%d)\n", rc);
        goto cleanup;
    }

    /* ---------- Results ---------- */
    printf("\n--- Results ---\n");
    printf("Public key buffer capacity:  %zu bytes\n", pub_len);
    printf("Private key buffer capacity: %zu bytes\n", priv_len);
    printf("Signature actual size:       %zu bytes\n", sig_len);
    printf("Key generation time:         %.3f ms\n", keygen_ms);
    printf("Signing time:                %.3f ms\n", sign_ms);
    printf("Verification time:           %.3f ms\n", verify_ms);

cleanup:
    free(priv); free(pub); free(sig);
    free(tmpkg); free(tmpsd); free(tmpvv);
    return (rc == 0) ? 0 : 2;
}
