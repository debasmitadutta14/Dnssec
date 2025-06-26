// ------------------- auth_server.c -------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define RRSET "example.com IN A 192.0.2.1"
#define TTL_SECONDS 3600

void fail() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

EVP_PKEY* create_rsa_key() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) fail();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) fail();

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) fail();
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void save_pem_key(EVP_PKEY *key, const char *priv, const char *pub) {
    FILE *fp = fopen(priv, "w");
    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

    fp = fopen(pub, "w");
    PEM_write_PUBKEY(fp, key);
    fclose(fp);
}

int sign_data(EVP_PKEY *key, const unsigned char *msg, size_t len, const char *outfile) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char *sig = NULL;
    size_t sig_len = 0;

    if (!ctx || EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) <= 0) fail();
    if (EVP_DigestSignUpdate(ctx, msg, len) <= 0) fail();
    EVP_DigestSignFinal(ctx, NULL, &sig_len);
    sig = malloc(sig_len);
    if (EVP_DigestSignFinal(ctx, sig, &sig_len) <= 0) fail();

    FILE *fp = fopen(outfile, "wb");
    fwrite(sig, 1, sig_len, fp);
    fclose(fp);

    free(sig);
    EVP_MD_CTX_free(ctx);
    return 1;
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_PKEY *ksk = create_rsa_key();
    EVP_PKEY *zsk = create_rsa_key();
    save_pem_key(ksk, "ksk_priv.pem", "ksk_pub.pem");
    save_pem_key(zsk, "zsk_priv.pem", "zsk_pub.pem");

    FILE *fp = fopen("dnskey.pem", "w");
    PEM_write_PUBKEY(fp, zsk);
    PEM_write_PUBKEY(fp, ksk);
    fclose(fp);

    fp = fopen("rrset.txt", "w");
    time_t expiry = time(NULL) + TTL_SECONDS;
    fprintf(fp, "%s | Expiry: %ld\n", RRSET, expiry);
    fclose(fp);

    fp = fopen("rrset.txt", "r");
    char buffer[512];
    fgets(buffer, sizeof(buffer), fp);
    fclose(fp);
    sign_data(zsk, (unsigned char*)buffer, strlen(buffer), "rrsig_rrset.bin");

    fp = fopen("dnskey.pem", "rb");
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    rewind(fp);
    unsigned char *data = malloc(len);
    fread(data, 1, len, fp);
    fclose(fp);
    sign_data(ksk, data, len, "rrsig_dnskey.bin");
    free(data);

    EVP_PKEY_free(ksk);
    EVP_PKEY_free(zsk);
    return 0;
}
