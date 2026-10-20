#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../src/ref/hqc.h"
#include "../src/ref/data_structures.h"
#include "parameters.h"

static void print_msg(const char *label, const uint64_t *m) {
    printf("%s: ", label);
    for (size_t i = 0; i < VEC_N1N2_SIZE_64; i++) {
        printf("%016lx ", (unsigned long)m[i]);
    }
    printf("\n");
}

static void xor_ciphertexts(ciphertext_pke_t *out,
                            const ciphertext_pke_t *c1,
                            const ciphertext_pke_t *c2) {
    for (size_t i = 0; i < VEC_N_SIZE_64; i++) {
        out->u[i] = c1->u[i] ^ c2->u[i];
        out->v[i] = c1->v[i] ^ c2->v[i];
    }
}

int main(void) {
    uint8_t pk[PUBLIC_KEY_BYTES] = {0};
    uint8_t sk[SECRET_KEY_BYTES] = {0};
    uint8_t seed[SEED_BYTES] = {3};

    ciphertext_pke_t c1 = {0};
    ciphertext_pke_t c2 = {0};
    ciphertext_pke_t csum = {0};

    uint64_t m1[VEC_N1N2_SIZE_64] = {0};
    uint64_t m2[VEC_N1N2_SIZE_64] = {0};
    uint64_t d1[VEC_N1N2_SIZE_64] = {0};
    uint64_t d2[VEC_N1N2_SIZE_64] = {0};
    uint64_t dsum[VEC_N1N2_SIZE_64] = {0};

    uint8_t theta1[SEED_BYTES] = {1};
    uint8_t theta2[SEED_BYTES] = {2};

    /* very small test messages */
    m1[0] = 1ULL;
    m2[0] = 1ULL;

    printf("Generating keypair...\n");
    hqc_pke_keygen(pk, sk, seed);

    printf("Encrypting m1...\n");
    hqc_pke_encrypt(&c1, pk, m1, theta1);

    printf("Encrypting m2...\n");
    hqc_pke_encrypt(&c2, pk, m2, theta2);

    printf("Decrypting c1...\n");
    hqc_pke_decrypt(d1, sk, &c1);

    printf("Decrypting c2...\n");
    hqc_pke_decrypt(d2, sk, &c2);

    printf("Building csum = c1 + c2 using XOR...\n");
    xor_ciphertexts(&csum, &c1, &c2);

    printf("Decrypting csum...\n");
    hqc_pke_decrypt(dsum, sk, &csum);

    print_msg("m1", m1);
    print_msg("m2", m2);
    print_msg("dec(c1)", d1);
    print_msg("dec(c2)", d2);
    print_msg("dec(c1+c2)", dsum);

    return 0;
}
