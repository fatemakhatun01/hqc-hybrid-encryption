#include <stdio.h>      
#include <stdint.h>     
#include <string.h>     
#include "api.h"        

#define PRIME_P 4294967291ULL   // Largest 32-bit prime below 2^32

/*
 * Print a byte array in hexadecimal.
 */
static void print_hex(const char *label, const uint8_t *x, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", x[i]);
    }
    printf("\n");
}

/*
 * Read 4 bytes as one 32-bit unsigned integer (big-endian style).
 * bytes[0] becomes the most significant byte.
 */
static uint32_t load_u32_be(const uint8_t b[4]) {
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  |
           ((uint32_t)b[3]);
}

/*
 * Store one 32-bit unsigned integer into 4 bytes (big-endian style).
 */
static void store_u32_be(uint8_t b[4], uint32_t x) {
    b[0] = (uint8_t)((x >> 24) & 0xFF);
    b[1] = (uint8_t)((x >> 16) & 0xFF);
    b[2] = (uint8_t)((x >> 8) & 0xFF);
    b[3] = (uint8_t)(x & 0xFF);
}

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0};     // public key
    uint8_t sk[CRYPTO_SECRETKEYBYTES] = {0};     // secret key
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES] = {0};    // HQC KEM ciphertext

    uint8_t ss1[CRYPTO_BYTES] = {0};             // shared secret from encapsulation
    uint8_t ss2[CRYPTO_BYTES] = {0};             // shared secret from decapsulation

    uint8_t m1[CRYPTO_BYTES] = {0};              // original 32-byte message
    uint8_t dem[CRYPTO_BYTES] = {0};             // DEM part (same length = 32 bytes)
    uint8_t m2[CRYPTO_BYTES] = {0};              // recovered message

    /*
     * Example message:
     * We use 8 blocks, each 4 bytes.
     * To keep each block safely below the prime, we set the top bit to 0
     * by using values less than 2^31.
     */
    uint32_t example_blocks[8] = {
        1, 2, 3, 4, 100, 200, 300, 400
    };

    for (size_t i = 0; i < 8; i++) {
        store_u32_be(&m1[4 * i], example_blocks[i]);
    }

    printf("PK bytes: %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("SK bytes: %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CT bytes: %d\n", CRYPTO_CIPHERTEXTBYTES);
    printf("SS bytes: %d\n", CRYPTO_BYTES);
    printf("Prime p: %llu\n", (unsigned long long)PRIME_P);

    /*
     * Step 1: Generate HQC-KEM keypair
     */
    printf("Generating KEM keypair...\n");
    if (crypto_kem_keypair(pk, sk) != 0) {
        printf("keypair failed\n");
        return 1;
    }

    /*
     * Step 2: Encapsulate to get:
     *   ct  = KEM ciphertext
     *   ss1 = shared secret
     */
    printf("Encapsulating to get CT and SS1...\n");
    if (crypto_kem_enc(ct, ss1, pk) != 0) {
        printf("encapsulation failed\n");
        return 1;
    }

    /*
     * Step 3: DEM encryption using modular arithmetic.
     *
     * Split ss1 and m1 into 8 chunks of 4 bytes.
     * For each chunk:
     *   s = ss1_i mod p
     *   m = m1_i mod p
     *   dem_i = (s + m) mod p
     *
     * Then store dem_i back into 4 bytes.
     */
    for (size_t i = 0; i < 8; i++) {
        uint32_t s_raw = load_u32_be(&ss1[4 * i]);               // 4-byte chunk from shared secret
        uint32_t m_raw = load_u32_be(&m1[4 * i]);                // 4-byte chunk from message

        uint64_t s = ((uint64_t)s_raw) % PRIME_P;                // reduce mod p
        uint64_t m = ((uint64_t)m_raw) % PRIME_P;                // reduce mod p

        uint32_t dem_block = (uint32_t)((s + m) % PRIME_P);      // modular addition

        store_u32_be(&dem[4 * i], dem_block);                    // write result back to DEM bytes
    }

    /*
     * At this point, the full ciphertext is conceptually:
     *   C = (ct, dem)
     */

    /*
     * Step 4: Decapsulate to recover ss2.
     */
    printf("Decapsulating CT to recover SS2...\n");
    if (crypto_kem_dec(ss2, ct, sk) != 0) {
        printf("decapsulation failed\n");
        return 1;
    }

    /*
     * Step 5: Recover message using modular subtraction.
     *
     * For each chunk:
     *   s = ss2_i mod p
     *   d = dem_i mod p
     *   m = (d - s) mod p
     *
     * To avoid negative values:
     *   m = (d + p - s) mod p
     */
    for (size_t i = 0; i < 8; i++) {
        uint32_t s_raw = load_u32_be(&ss2[4 * i]);               // recovered shared secret chunk
        uint32_t d_raw = load_u32_be(&dem[4 * i]);               // encrypted DEM chunk

        uint64_t s = ((uint64_t)s_raw) % PRIME_P;                // reduce mod p
        uint64_t d = ((uint64_t)d_raw) % PRIME_P;                // reduce mod p

        uint32_t m_block = (uint32_t)((d + PRIME_P - s) % PRIME_P); // modular subtraction

        store_u32_be(&m2[4 * i], m_block);                       // write recovered block into m2
    }

    print_hex("Original message m1", m1, CRYPTO_BYTES);
    print_hex("Recovered message m2", m2, CRYPTO_BYTES);

    if (memcmp(m1, m2, CRYPTO_BYTES) == 0) {
        printf("SUCCESS: modular decrypted message matches original message\n");
    } else {
        printf("FAIL: modular decrypted message does not match original message\n");
    }

    return 0;
}

