/*
 * rsa_ksk_dnssec.c - RSA-2048 KSK generator and signer using EVP (OpenSSL 3+)
 *
 * Generates a 2048-bit RSA keypair, signs a DNSKEY RRset, verifies the signature,
 * and saves the private/public keys to PEM files.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <time.h>

/* Measure elapsed time in milliseconds */
static double elapsed_ms(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1000.0
         + (double)(b.tv_nsec - a.tv_nsec) / 1e6;
}

int main(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char *sig = NULL;
    size_t siglen;
    int rc;
    struct timespec t0, t1;
    double sign_latency, verify_latency;
    size_t key_size = 0;

    /* Example DNSKEY RRset (replace with actual RRset bytes) */
    const uint8_t dnskey_rrset[] = {0x00,0x01,0x02,0x03,0x04,0x05};
    size_t dnskey_len = sizeof(dnskey_rrset);

    /* Initialize OpenSSL */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /* ---------- Generate RSA-2048 key pair ---------- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) { ERR_print_errors_fp(stderr); exit(1); }
    if (EVP_PKEY_keygen_init(pctx) <= 0) { ERR_print_errors_fp(stderr); exit(1); }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) { ERR_print_errors_fp(stderr); exit(1); }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { ERR_print_errors_fp(stderr); exit(1); }
    EVP_PKEY_CTX_free(pctx);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("RSA-2048 KSK generated (%.3f ms)\n", elapsed_ms(t0,t1));

    /* ---------- Save private key ---------- */
    FILE *f = fopen("rsa_ksk_priv.pem", "wb");
    if (!f) { perror("fopen"); exit(1); }
    PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    /* ---------- Save public key ---------- */
    f = fopen("rsa_ksk_pub.pem", "wb");
    if (!f) { perror("fopen"); exit(1); }
    PEM_write_PUBKEY(f, pkey);
    fclose(f);
    printf("Keys saved to 'rsa_ksk_priv.pem' and 'rsa_ksk_pub.pem'\n");

    /* ---------- Get DNSKEY key size (modulus size in bytes) ---------- */
    BIGNUM *n_bn = NULL;
    if (EVP_PKEY_get_bn_param(pkey, "n", &n_bn)) {
        key_size = BN_num_bytes(n_bn);
        printf("DNSKEY key size: %zu bytes\n", key_size);
        BN_free(n_bn);
    } else {
        fprintf(stderr, "Failed to get RSA modulus\n");
    }

    /* ---------- Sign DNSKEY RRset ---------- */
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) { ERR_print_errors_fp(stderr); exit(1); }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) { ERR_print_errors_fp(stderr); exit(1); }

    /* Determine signature length */
    if (EVP_DigestSign(mdctx, NULL, &siglen, dnskey_rrset, dnskey_len) <= 0) { ERR_print_errors_fp(stderr); exit(1); }

    sig = malloc(siglen);
    if (!sig) { perror("malloc"); exit(1); }

    /* Generate signature */
    if (EVP_DigestSign(mdctx, sig, &siglen, dnskey_rrset, dnskey_len) <= 0) { ERR_print_errors_fp(stderr); exit(1); }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    sign_latency = elapsed_ms(t0,t1);
    printf("DNSKEY RRset signed, signature length: %zu bytes (%.3f ms)\n", siglen, sign_latency);

    /* ---------- Verify signature ---------- */
    EVP_MD_CTX *vrfy_ctx = EVP_MD_CTX_new();
    if (!vrfy_ctx) { ERR_print_errors_fp(stderr); exit(1); }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (EVP_DigestVerifyInit(vrfy_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) { ERR_print_errors_fp(stderr); exit(1); }

    rc = EVP_DigestVerify(vrfy_ctx, sig, siglen, dnskey_rrset, dnskey_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    verify_latency = elapsed_ms(t0,t1);
    if (rc == 1) {
        printf("DNSKEY signature verification SUCCESSFUL (%.3f ms)\n", verify_latency);
    } else if (rc == 0) {
        printf("DNSKEY signature verification FAILED (%.3f ms)\n", verify_latency);
    } else {
        ERR_print_errors_fp(stderr);
    }

    /* ---------- Print summary ---------- */
    printf("\n==== METRICS ====\n");
    printf("DNSKEY Key Size: %zu bytes\n", key_size);
    printf("RRSIG (Signature) Size: %zu bytes\n", siglen);
    printf("Signing Latency: %.3f ms\n", sign_latency);
    printf("Verification Latency: %.3f ms\n", verify_latency);

    /* ---------- Cleanup ---------- */
    EVP_MD_CTX_free(mdctx);
    EVP_MD_CTX_free(vrfy_ctx);
    EVP_PKEY_free(pkey);
    free(sig);
    ERR_free_strings();
    EVP_cleanup();

    return 0;
}
