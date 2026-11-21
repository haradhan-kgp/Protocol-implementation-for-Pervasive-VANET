#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <oqs/oqs.h>

#define NONCE_LEN 16
#define KEY_LEN 32
#define PSN_LEN 32

/* ===================== Utility ===================== */

void random_bytes(unsigned char *buf, int len) {
    for (int i = 0; i < len; i++)
        buf[i] = rand() % 256;
}

/* ===================== HASH ===================== */

void hash(unsigned char *input, int len, unsigned char *output) {
    SHA256(input, len, output);
}

/* ===================== HMAC ===================== */

void compute_hmac(unsigned char *key, int keylen,
                  unsigned char *data, int datalen,
                  unsigned char *out) {
    unsigned int len;
    HMAC(EVP_sha256(), key, keylen, data, datalen, out, &len);
}

/* ===================== AEAD (AES-GCM) ===================== */

void aead_encrypt(unsigned char *key,
                  unsigned char *plaintext, int plen,
                  unsigned char *ciphertext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[12] = {0};
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plen);

    EVP_CIPHER_CTX_free(ctx);
}

/* ===================== KDF ===================== */

void kdf(unsigned char *input, int len, unsigned char *output) {
    hash(input, len, output);
}

/* ===================== PUF + FE (Simulated) ===================== */

// Gen(PUF)
void FE_Gen(unsigned char *puf, unsigned char *sigma, unsigned char *hd) {
    hash(puf, 32, sigma);
    memcpy(hd, puf, 32); // helper data (simulated)
}

// Rep(PUF, hd)
void FE_Rep(unsigned char *puf, unsigned char *hd, unsigned char *sigma) {
    hash(puf, 32, sigma); // reconstruct
}

/* ===================== GLOBAL STRUCTS ===================== */

typedef struct {
    OQS_KEM *kem;
    uint8_t *pk;
    uint8_t *sk;
} Entity;

/* ===================== MAIN ===================== */

int main() {
    srand(time(NULL));

    printf("=== Protocol Simulation Start ===\n");

    /* ---------- INIT KYBER ---------- */
    Entity O, R;

    O.kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    R.kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);

    O.pk = malloc(O.kem->length_public_key);
    O.sk = malloc(O.kem->length_secret_key);

    R.pk = malloc(R.kem->length_public_key);
    R.sk = malloc(R.kem->length_secret_key);

    OQS_KEM_keypair(O.kem, O.pk, O.sk);
    OQS_KEM_keypair(R.kem, R.pk, R.sk);

    /* ---------- PUF ENROLLMENT ---------- */
    unsigned char puf[32], sigma[32], hd[32];
    random_bytes(puf, 32);

    FE_Gen(puf, sigma, hd);

    /* ---------- REGISTRATION ---------- */
    unsigned char PSN[PSN_LEN];
    hash(puf, 32, PSN); // simplified PSN

    /* ---------- AUTHENTICATION ---------- */

    /* STEP 1: RSU broadcast */
    printf("RSU Broadcast\n");

    /* STEP 2: Vehicle request */

    unsigned char puf_new[32], sigma_rec[32];
    random_bytes(puf_new, 32);

    FE_Rep(puf_new, hd, sigma_rec);

    unsigned char auth_input[96];
    memcpy(auth_input, sigma_rec, 32);
    memcpy(auth_input + 32, PSN, 32);
    memcpy(auth_input + 64, "RSU1", 4);

    unsigned char AuthK[32];
    hash(auth_input, 68, AuthK);

    unsigned char nO[NONCE_LEN];
    random_bytes(nO, NONCE_LEN);

    uint8_t *ctOR = malloc(R.kem->length_ciphertext);
    uint8_t KO_R[KEY_LEN];

    OQS_KEM_encaps(R.kem, ctOR, KO_R, R.pk);

    unsigned char M1[32];
    compute_hmac(AuthK, 32, ctOR, R.kem->length_ciphertext, M1);

    printf("Vehicle -> RSU: M1 sent\n");

    /* STEP 3: RSU response */

    uint8_t KO_R_dec[KEY_LEN];
    OQS_KEM_decaps(R.kem, KO_R_dec, ctOR, R.sk);

    uint8_t *ctRO = malloc(O.kem->length_ciphertext);
    uint8_t KR_O[KEY_LEN];

    OQS_KEM_encaps(O.kem, ctRO, KR_O, O.pk);

    unsigned char nR[NONCE_LEN];
    random_bytes(nR, NONCE_LEN);

    unsigned char sess_input[128];
    memcpy(sess_input, KO_R_dec, 32);
    memcpy(sess_input + 32, KR_O, 32);
    memcpy(sess_input + 64, PSN, 32);
    memcpy(sess_input + 96, nO, 16);
    memcpy(sess_input + 112, nR, 16);

    unsigned char Ksess_R[32];
    kdf(sess_input, 128, Ksess_R);

    printf("RSU -> Vehicle: M2 sent\n");

    /* STEP 4: Vehicle final */

    uint8_t KR_O_dec[KEY_LEN];
    OQS_KEM_decaps(O.kem, KR_O_dec, ctRO, O.sk);

    unsigned char sess_input2[128];
    memcpy(sess_input2, KO_R, 32);
    memcpy(sess_input2 + 32, KR_O_dec, 32);
    memcpy(sess_input2 + 64, PSN, 32);
    memcpy(sess_input2 + 96, nO, 16);
    memcpy(sess_input2 + 112, nR, 16);

    unsigned char Ksess_O[32];
    kdf(sess_input2, 128, Ksess_O);

    /* M3 */
    unsigned char M3[32];
    compute_hmac(Ksess_O, 32, nR, NONCE_LEN, M3);

    printf("Vehicle -> RSU: M3 sent\n");

    /* ---------- VERIFY ---------- */

    if (memcmp(Ksess_O, Ksess_R, 32) == 0) {
        printf("SUCCESS: Session keys match!\n");
    } else {
        printf("FAIL: Keys mismatch!\n");
    }

    printf("=== Protocol Complete ===\n");

    return 0;
}