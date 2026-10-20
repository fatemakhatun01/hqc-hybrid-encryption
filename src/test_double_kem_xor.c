#include <stdio.h>      
#include <stdint.h>     
#include <string.h>     
#include "api.h"        

/*
 * Helper function:
 * Print a byte array in hexadecimal.
 * This is useful for showing m1, m2, expected result, and recovered result.
 */
static void print_hex(const char *label, const uint8_t *x, size_t len) {
    printf("%s: ", label);                     // Print label first
    for (size_t i = 0; i < len; i++) {        // Loop over all bytes
        printf("%02x", x[i]);                 // Print each byte in 2-digit hex
    }
    printf("\n");                             
}

int main(void) {

    /*
     *  Generate one HQC-KEM keypair.
     *
     * pk = public key
     * sk = secret key
     */
    uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0};
    uint8_t sk[CRYPTO_SECRETKEYBYTES] = {0};

    /*
     * We need two separate KEM ciphertexts.
     *
     * ct1 corresponds to the first encapsulation
     * ct2 corresponds to the second encapsulation
     */
    uint8_t ct1[CRYPTO_CIPHERTEXTBYTES] = {0};
    uint8_t ct2[CRYPTO_CIPHERTEXTBYTES] = {0};

    /*
     * Shared secrets generated during encapsulation.
     *
     * ss1 belongs to ct1
     * ss2 belongs to ct2
     */
    uint8_t ss1[CRYPTO_BYTES] = {0};
    uint8_t ss2[CRYPTO_BYTES] = {0};

    /*
     * Shared secrets recovered during decapsulation.
     *
     * ss1r = recovered secret from ct1
     * ss2r = recovered secret from ct2
     */
    uint8_t ss1r[CRYPTO_BYTES] = {0};
    uint8_t ss2r[CRYPTO_BYTES] = {0};

    /*
     * Two input messages.
     * Each message has the same size as the shared secret (32 bytes in HQC-1).
     */
    uint8_t m1[CRYPTO_BYTES] = {0};
    uint8_t m2[CRYPTO_BYTES] = {0};

    /*
     * DEM parts.
     *
     * dem1 = m1 XOR ss1
     * dem2 = m2 XOR ss2
     */
    uint8_t dem1[CRYPTO_BYTES] = {0};
    uint8_t dem2[CRYPTO_BYTES] = {0};

    /*
     * Combined DEM part.
     *
     * dem_sum = dem1 XOR dem2
     *         = (m1 XOR ss1) XOR (m2 XOR ss2)
     */
    uint8_t dem_sum[CRYPTO_BYTES] = {0};

    /*
     * Expected and recovered final outputs.
     *
     * expected = m1 XOR m2
     * recovered = dem_sum XOR ss1r XOR ss2r
     */
    uint8_t expected[CRYPTO_BYTES] = {0};
    uint8_t recovered[CRYPTO_BYTES] = {0};

    /*
     * Fill m1 with example values:
     * 01, 02, 03, ..., 20
     */
    for (size_t i = 0; i < CRYPTO_BYTES; i++) {
        m1[i] = (uint8_t)(i + 1);
    }

    /*
     * Fill m2 with another example pattern:
     * a0, a1, a2, ...
     */
    for (size_t i = 0; i < CRYPTO_BYTES; i++) {
        m2[i] = (uint8_t)(0xA0 + i);
    }

    /*
     * Print object sizes for reference.
     */
    printf("PK bytes: %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("SK bytes: %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CT bytes: %d\n", CRYPTO_CIPHERTEXTBYTES);
    printf("SS bytes: %d\n", CRYPTO_BYTES);

    /*
     * Generate the HQC-KEM keypair.
     */
    printf("Generating KEM keypair...\n");
    if (crypto_kem_keypair(pk, sk) != 0) {
        printf("keypair failed\n");
        return 1;
    }

    /*
     * First encapsulation:
     * Using pk, generate ct1 and ss1.
     *
     * This corresponds to:
     * c1 = KEM(pk, ss1)
     */
    printf("Encapsulating c1...\n");
    if (crypto_kem_enc(ct1, ss1, pk) != 0) {
        printf("encapsulation c1 failed\n");
        return 1;
    }

    /*
     * Second encapsulation:
     * Using the same public key pk, generate ct2 and ss2.
     *
     * This corresponds to:
     * c2 = KEM(pk, ss2)
     */
    printf("Encapsulating c2...\n");
    if (crypto_kem_enc(ct2, ss2, pk) != 0) {
        printf("encapsulation c2 failed\n");
        return 1;
    }

    /*
     * Compute DEM part for c1:
     *
     * dem1 = m1 XOR ss1
     */
    for (size_t i = 0; i < CRYPTO_BYTES; i++) {
        dem1[i] = m1[i] ^ ss1[i];
    }

    /*
     * Compute DEM part for c2:
     *
     * dem2 = m2 XOR ss2
     */
    for (size_t i = 0; i < CRYPTO_BYTES; i++) {
        dem2[i] = m2[i] ^ ss2[i];
    }

    /*
     * Compute combined DEM part:
     *
     * dem_sum = dem1 XOR dem2
     *         = (m1 XOR ss1) XOR (m2 XOR ss2)
     */
    for (size_t i = 0; i < CRYPTO_BYTES; i++) {
        dem_sum[i] = dem1[i] ^ dem2[i];
    }

    /*
     * The combined ciphertext is conceptually:
     *
     * c' = (ct1, ct2, dem_sum)
     *
     * Notice:
     * We are not adding HQC ciphertexts directly.
     * We are storing both KEM ciphertexts separately,
     * and only combining the DEM parts using XOR.
     */

    /*
     * Decapsulate ct1 to recover ss1r.
     */
    printf("Decapsulating c1...\n");
    if (crypto_kem_dec(ss1r, ct1, sk) != 0) {
        printf("decapsulation c1 failed\n");
        return 1;
    }


    /*
     * Decapsulate ct2 to recover ss2r.
     */
    printf("Decapsulating c2...\n");
    if (crypto_kem_dec(ss2r, ct2, sk) != 0) {
        printf("decapsulation c2 failed\n");
        return 1;
    }

    /*
     * Recover final combined plaintext:
     *
     * recovered = dem_sum XOR ss1r XOR ss2r
     *
     * Algebra:
     * recovered
     * = [(m1 XOR ss1) XOR (m2 XOR ss2)] XOR ss1 XOR ss2
     * = m1 XOR m2
     *
     * because ss1 XOR ss1 = 0
     * and ss2 XOR ss2 = 0
     */
    for (size_t i = 0; i < CRYPTO_BYTES; i++) {
        recovered[i] = dem_sum[i] ^ ss1r[i] ^ ss2r[i];
    }

    /*
     * Compute expected result directly:
     *
     * expected = m1 XOR m2
     *
     * This is what the recovered output should match.
     */
    for (size_t i = 0; i < CRYPTO_BYTES; i++) {
        expected[i] = m1[i] ^ m2[i];
    }

    /*
     * Print all relevant values.
     */
    print_hex("m1", m1, CRYPTO_BYTES);
    print_hex("m2", m2, CRYPTO_BYTES);
    print_hex("expected = m1 XOR m2", expected, CRYPTO_BYTES);
    print_hex("recovered", recovered, CRYPTO_BYTES);

    /*
     * Final correctness check:
     * Compare recovered output with expected = m1 XOR m2.
     */
    if (memcmp(expected, recovered, CRYPTO_BYTES) == 0) {
        printf("SUCCESS: recovered value matches m1 XOR m2\n");
    } else {
        printf("FAIL: recovered value does not match m1 XOR m2\n");
    }

    return 0;
}
