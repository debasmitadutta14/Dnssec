// ------------------- resolver.c -------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void fail() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

int verify_sig(EVP_PKEY *key, unsigned char *msg, size_t msg_len, unsigned char *sig, size_t sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) <= 0) fail();
    if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) <= 0) fail();
    int ok = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    EVP_MD_CTX_free(ctx);
    return ok;
}

EVP_PKEY* load_key(const char *file) {
    FILE *fp = fopen(file, "r");
    EVP_PKEY *key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return key;
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_PKEY *ksk = load_key("ksk_pub.pem");
    EVP_PKEY *zsk = load_key("zsk_pub.pem");

    FILE *fp = fopen("dnskey.pem", "rb");
    fseek(fp, 0, SEEK_END);
    long dlen = ftell(fp);
    rewind(fp);
    unsigned char *dnskey_data = malloc(dlen);
    fread(dnskey_data, 1, dlen, fp);
    fclose(fp);

    fp = fopen("rrsig_dnskey.bin", "rb");
    fseek(fp, 0, SEEK_END);
    long siglen1 = ftell(fp);
    rewind(fp);
    unsigned char *sig1 = malloc(siglen1);
    fread(sig1, 1, siglen1, fp);
    fclose(fp);

    printf("\n🔎 Validating DNSKEY RRSET using KSK...\n");
    if (verify_sig(ksk, dnskey_data, dlen, sig1, siglen1) == 1)
        printf("✔️  DNSKEY Signature Valid\n");
    else
        printf("❌ DNSKEY Signature Invalid\n");

    char buffer[512];
    fp = fopen("rrset.txt", "r");
    fgets(buffer, sizeof(buffer), fp);
    fclose(fp);

    fp = fopen("rrsig_rrset.bin", "rb");
    fseek(fp, 0, SEEK_END);
    long siglen2 = ftell(fp);
    rewind(fp);
    unsigned char *sig2 = malloc(siglen2);
    fread(sig2, 1, siglen2, fp);
    fclose(fp);

    printf("\n🔎 Validating RRSET using ZSK...\n");
    if (verify_sig(zsk, (unsigned char*)buffer, strlen(buffer), sig2, siglen2) == 1) {
        printf("✔️  RRSET Signature Valid\n");
        long expiry;
        sscanf(buffer, "%*[^|]| Expiry: %ld", &expiry);
        if (time(NULL) <= expiry)
            printf("🕒 TTL Valid\n");
        else
            printf("❌ TTL Expired\n");
    } else {
        printf("❌ RRSET Signature Invalid\n");
    }

    free(dnskey_data);
    free(sig1);
    free(sig2);
    EVP_PKEY_free(ksk);
    EVP_PKEY_free(zsk);
    return 0;
}
