/*
 * falcon_ksk.c - KSK (Key Signing Key) generator and signer using Falcon-512
 * Round-3 reference implementation.
 *
 * Generates a Falcon-512 keypair, signs a DNSKEY RRset, verifies the signature,
 * and saves the private/public keys to files.
 *
 * Notes:
 * - This file assumes the Falcon reference API/macros from your repo
 *   (FALCON_PRIVKEY_SIZE, FALCON_TMPSIZE_*, falcon_keygen_make, falcon_sign_dyn,
 *   falcon_verify, and the shake256 PRNG helpers).
 * - It focuses on robustness (checks for fopen/fwrite, proper init of variables).
 */

#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "falcon.h"

/* Use Falcon-512 parameter */
#define LOGN 9   /* Falcon-512 */

/* Measure elapsed time in milliseconds */
static double elapsed_ms(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1000.0
         + (double)(b.tv_nsec - a.tv_nsec) / 1e6;
}

int main(void)
{
    unsigned logn = LOGN;
    int rc = 0; /* default success, set non-zero on failures */

    /* Sizes from Falcon macros */
    size_t priv_len = (size_t)FALCON_PRIVKEY_SIZE(logn);
    size_t pub_len  = (size_t)FALCON_PUBKEY_SIZE(logn);
    size_t sig_max  = (size_t)FALCON_SIG_COMPRESSED_MAXSIZE(logn);

    size_t tmpkg_len = (size_t)FALCON_TMPSIZE_KEYGEN(logn);
    size_t tmpsd_len = (size_t)FALCON_TMPSIZE_SIGNDYN(logn);
    size_t tmpvv_len = (size_t)FALCON_TMPSIZE_VERIFY(logn);

    printf("=== Falcon-512 KSK Generator ===\n");
    printf("Macro sizes: priv=%zu pub=%zu sig_max=%zu\n", priv_len, pub_len, sig_max);
    printf("Tmp sizes: keygen=%zu sign_dyn=%zu verify=%zu\n", tmpkg_len, tmpsd_len, tmpvv_len);

    /* Allocate buffers */
    uint8_t *priv = malloc(priv_len);
    uint8_t *pub  = malloc(pub_len);
    uint8_t *sig  = malloc(sig_max);
    uint8_t *tmpkg = malloc(tmpkg_len);
    uint8_t *tmpsd = malloc(tmpsd_len);
    uint8_t *tmpvv = malloc(tmpvv_len);

    if (!priv || !pub || !sig || !tmpkg || !tmpsd || !tmpvv) {
        fprintf(stderr, "malloc failed\n");
        rc = 1;
        goto cleanup;
    }

    /* Deterministic seed for reproducibility; replace with secure RNG in production */
    shake256_context rng;
    const uint8_t seed[] = "falcon-ksk-seed";
    /* initialize PRNG from seed (reference impl provides this helper) */
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed) - 1);

    struct timespec t0, t1;
    double keygen_ms = 0.0, sign_ms = 0.0, verify_ms = 0.0;
    size_t sig_len = sig_max;

    /* ---------- Key generation ---------- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = falcon_keygen_make(&rng, logn,
                            priv, priv_len,
                            pub,  pub_len,
                            tmpkg, tmpkg_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    keygen_ms = elapsed_ms(t0, t1);

    if (rc != 0) {
        fprintf(stderr, "Key generation failed (rc=%d)\n", rc);
        goto cleanup;
    }
    printf("KSK keypair generated successfully\n");

    /* Save keys to files (with basic error checking) */
    FILE *f = fopen("ksk_priv.key", "wb");
    if (!f) {
        perror("fopen ksk_priv.key");
        rc = 2;
        goto cleanup;
    }
    if (fwrite(priv, 1, priv_len, f) != priv_len) {
        fprintf(stderr, "fwrite failed for ksk_priv.key\n");
        fclose(f);
        rc = 3;
        goto cleanup;
    }
    fclose(f);

    f = fopen("ksk_pub.key", "wb");
    if (!f) {
        perror("fopen ksk_pub.key");
        rc = 4;
        goto cleanup;
    }
    if (fwrite(pub, 1, pub_len, f) != pub_len) {
        fprintf(stderr, "fwrite failed for ksk_pub.key\n");
        fclose(f);
        rc = 5;
        goto cleanup;
    }
    fclose(f);
    printf("KSK keys saved to 'ksk_priv.key' and 'ksk_pub.key'\n");

    /* ---------- Prepare DNSKEY RRset ---------- */
    /* Example DNSKEY RRset in wire format (replace with real RRset in production) */
    const uint8_t dnskey_rrset[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05
    };
    size_t dnskey_len = sizeof(dnskey_rrset);

    /* ---------- Sign DNSKEY RRset (KSK signing) ---------- */
    /* Ensure sig_len is set to maximum buffer size before signing */
    sig_len = sig_max;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = falcon_sign_dyn(&rng,
                         sig, &sig_len, FALCON_SIG_COMPRESSED,
                         priv, priv_len,
                         dnskey_rrset, dnskey_len,
                         tmpsd, tmpsd_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    sign_ms = elapsed_ms(t0, t1);

    if (rc != 0) {
        fprintf(stderr, "KSK signing failed (rc=%d)\n", rc);
        goto cleanup;
    }
    printf("KSK signed DNSKEY RRset, sig_len=%zu bytes\n", sig_len);

    /* ---------- Verify signature ---------- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = falcon_verify(sig, sig_len, FALCON_SIG_COMPRESSED,
                       pub, pub_len,
                       dnskey_rrset, dnskey_len,
                       tmpvv, tmpvv_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    verify_ms = elapsed_ms(t0, t1);

    if (rc != 0) {
        fprintf(stderr, "KSK verification failed (rc=%d)\n", rc);
        goto cleanup;
    }
    printf("KSK signature verified successfully\n");

    /* ---------- Results ---------- */
    printf("\n--- Results ---\n");
    printf("Private key size: %zu bytes\n", priv_len);
    printf("Public key size:  %zu bytes\n", pub_len);
    printf("Signature size:   %zu bytes\n", sig_len);
    printf("Key generation time: %.3f ms\n", keygen_ms);
    printf("Signing time:        %.3f ms\n", sign_ms);
    printf("Verification time:   %.3f ms\n", verify_ms);

cleanup:
    /* Zero private sensitive material before freeing */
    if (priv) {
        memset(priv, 0, priv_len);
    }

    free(priv); free(pub); free(sig);
    free(tmpkg); free(tmpsd); free(tmpvv);

    return (rc == 0) ? 0 : 2;
}
