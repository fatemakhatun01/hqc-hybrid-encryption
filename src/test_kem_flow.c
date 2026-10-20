#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0};
    uint8_t sk[CRYPTO_SECRETKEYBYTES] = {0};
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES] = {0};
    uint8_t ss1[CRYPTO_BYTES] = {0};
    uint8_t ss2[CRYPTO_BYTES] = {0};

    printf("PK bytes: %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("SK bytes: %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CT bytes: %d\n", CRYPTO_CIPHERTEXTBYTES);
    printf("SS bytes: %d\n", CRYPTO_BYTES);

    printf("Generating KEM keypair...\n");
    if (crypto_kem_keypair(pk, sk) != 0) {
        printf("keypair failed\n");
        return 1;
    }

    printf("Encapsulating...\n");
    if (crypto_kem_enc(ct, ss1, pk) != 0) {
        printf("encapsulation failed\n");
        return 1;
    }

    printf("Decapsulating...\n");
    if (crypto_kem_dec(ss2, ct, sk) != 0) {
        printf("decapsulation failed\n");
        return 1;
    }

    if (memcmp(ss1, ss2, CRYPTO_BYTES) == 0) {
        printf("SUCCESS: shared secrets match\n");
    } else {
        printf("FAIL: shared secrets do not match\n");
    }

    return 0;
}
