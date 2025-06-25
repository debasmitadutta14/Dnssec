#include <stdio.h>           // Standard input/output functions
#include <stdlib.h>          // Memory management and exit functions
#include <string.h>          // String manipulation functions
#include <time.h>            // Time-related functions
#include <openssl/evp.h>     // High-level cryptographic functions
#include <openssl/pem.h>     // Read/write PEM keys
#include <openssl/err.h>     // Error handling functions

// Base DNS Resource Record Set (RRSET)
#define RRSET "example.com IN A 192.0.2.1"

// TTL for RRSET in seconds (e.g., 1 hour)
#define TTL_SECONDS 3600

// Print OpenSSL errors and exit
void fail() {
    ERR_print_errors_fp(stderr); // Print detailed OpenSSL errors
    exit(1);                     // Terminate program
}

// Generate a 2048-bit RSA key
EVP_PKEY* create_rsa_key() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Create key context for RSA
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) fail();          // Initialize keygen
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) fail();// Set key size to 2048 bits

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) fail();                // Generate key
    EVP_PKEY_CTX_free(ctx);                                      // Free context
    return pkey;                                                 // Return generated key
}

// Save private and public keys to files
void save_keys(EVP_PKEY *key, const char *priv, const char *pub) {
    FILE *fp = fopen(priv, "w");                                // Open private key file
    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);   // Write private key in PEM
    fclose(fp);

    fp = fopen(pub, "w");                                       // Open public key file
    PEM_write_PUBKEY(fp, key);                                  // Write public key in PEM
    fclose(fp);
}

// Load private key from file
EVP_PKEY* load_private(const char *file) {
    FILE *fp = fopen(file, "r");                                // Open file for reading
    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);  // Load private key
    fclose(fp);
    return key;
}

// Load public key from file
EVP_PKEY* load_public(const char *file) {
    FILE *fp = fopen(file, "r");                                // Open file for reading
    EVP_PKEY *key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);      // Load public key
    fclose(fp);
    return key;
}

// Sign a message using a private key
int sign_msg(EVP_PKEY *key, const unsigned char *msg, size_t len, unsigned char **sig, size_t *sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();                         // Create digest context
    if (!ctx || EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) <= 0) fail();
    if (EVP_DigestSignUpdate(ctx, msg, len) <= 0) fail();

    EVP_DigestSignFinal(ctx, NULL, sig_len);                    // Get signature length
    *sig = malloc(*sig_len);                                    // Allocate memory for signature
    if (EVP_DigestSignFinal(ctx, *sig, sig_len) <= 0) fail();   // Generate signature

    EVP_MD_CTX_free(ctx);                                       // Clean up
    return 1;
}

// Verify a message's signature using a public key
int verify_msg(EVP_PKEY *key, const unsigned char *msg, size_t len, unsigned char *sig, size_t sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();                         // Create digest context
    if (!ctx || EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) <= 0) fail();
    if (EVP_DigestVerifyUpdate(ctx, msg, len) <= 0) fail();

    int ok = EVP_DigestVerifyFinal(ctx, sig, sig_len);          // Verify the signature
    EVP_MD_CTX_free(ctx);                                       // Clean up
    return ok;                                                  // Return 1 if valid
}

int main() {
    OpenSSL_add_all_algorithms();   // Load OpenSSL algorithms
    ERR_load_crypto_strings();      // Load error strings

    // Step 1: Generate KSK and ZSK
    EVP_PKEY *ksk = create_rsa_key();  // Key Signing Key
    EVP_PKEY *zsk = create_rsa_key();  // Zone Signing Key
    save_keys(ksk, "ksk_priv.pem", "ksk_pub.pem"); // Save KSK keys
    save_keys(zsk, "zsk_priv.pem", "zsk_pub.pem"); // Save ZSK keys

    // Step 2: Append expiration timestamp to RRSET
    time_t current_time = time(NULL);                  // Current time
    time_t expiry_time = current_time + TTL_SECONDS;   // Expiry = now + TTL
    char full_rrset[512];                              // Buffer for RRSET + timestamp
    snprintf(full_rrset, sizeof(full_rrset), "%s | Expiry: %ld", RRSET, expiry_time); // Append timestamp

    // Step 3: Sign the timestamped RRSET using ZSK
    unsigned char *rr_sig = NULL;
    size_t rr_sig_len = 0;
    sign_msg(zsk, (unsigned char *)full_rrset, strlen(full_rrset), &rr_sig, &rr_sig_len);

    // Step 4: Sign the ZSK public key with KSK (simulated DNSKEY RRSIG)
    FILE *fp = fopen("zsk_pub.pem", "rb");
    fseek(fp, 0, SEEK_END);
    long zsk_pub_len = ftell(fp);
    rewind(fp);
    unsigned char *zsk_data = malloc(zsk_pub_len);
    fread(zsk_data, 1, zsk_pub_len, fp);
    fclose(fp);

    unsigned char *zsk_sig = NULL;
    size_t zsk_sig_len = 0;
    sign_msg(ksk, zsk_data, zsk_pub_len, &zsk_sig, &zsk_sig_len);

    // Step 5: Verify RRSET and TTL
    EVP_PKEY *zsk_pub = load_public("zsk_pub.pem");
    printf("\n✅ Verifying RRSET with ZSK...\n");
    if (verify_msg(zsk_pub, (unsigned char *)full_rrset, strlen(full_rrset), rr_sig, rr_sig_len) == 1) {
        printf("✔️  RRSET Signature Valid\n");

        // Extract expiry timestamp
        long extracted_expiry;
        sscanf(full_rrset, "%*[^|]| Expiry: %ld", &extracted_expiry); // Parse expiry
        if (time(NULL) <= extracted_expiry) {
            printf("🕒 TTL Valid (not expired)\n");
        } else {
            printf("❌ TTL Expired\n");
        }
    } else {
        printf("❌ RRSET Signature Invalid\n");
    }

    // Step 6: Verify ZSK using KSK
    EVP_PKEY *ksk_pub = load_public("ksk_pub.pem");
    printf("\n✅ Verifying ZSK with KSK...\n");
    printf(verify_msg(ksk_pub, zsk_data, zsk_pub_len, zsk_sig, zsk_sig_len) == 1
           ? "✔️  ZSK Signature Valid\n" : "❌  ZSK Signature Invalid\n");

    // Step 7: Cleanup
    EVP_PKEY_free(ksk);
    EVP_PKEY_free(zsk);
    EVP_PKEY_free(ksk_pub);
    EVP_PKEY_free(zsk_pub);
    free(rr_sig);
    free(zsk_sig);
    free(zsk_data);

    return 0;
}
