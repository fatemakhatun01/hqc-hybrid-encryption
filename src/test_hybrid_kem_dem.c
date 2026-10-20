#include <stdio.h>      
#include <stdint.h>     
#include <string.h>     
#include "api.h"        
                       

/*
 * Helper function to print a byte array in hexadecimal.
 * This is useful for showing the original and recovered messages.
 */
static void print_hex(const char *label, const uint8_t *x, size_t len) { // label = text to print first,
                                                                         // x = byte array to print,
                                                                         // len = number of bytes.
    printf("%s: ", label);                                               // Print the label first.
    for (size_t i = 0; i < len; i++) {                                   // Loop through all bytes.
        printf("%02x", x[i]);                                            // Print each byte as 2-digit hex.
    }
    printf("\n");                                                        // Move to the next line after printing.
}

int main(void) {                                                         // Main function where the program starts.

    uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0};                             // Public key array. Size is fixed by HQC.
    uint8_t sk[CRYPTO_SECRETKEYBYTES] = {0};                             // Secret key array. Size is fixed by HQC.
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES] = {0};                            // KEM ciphertext array. Produced by encapsulation.

    uint8_t ss1[CRYPTO_BYTES] = {0};                                     // Shared secret from encapsulation (sender side).
    uint8_t ss2[CRYPTO_BYTES] = {0};                                     // Shared secret from decapsulation (receiver side).

    uint8_t m1[CRYPTO_BYTES] = {0};                                      // Original plaintext message.
    uint8_t dem[CRYPTO_BYTES] = {0};                                     // DEM part: encrypted message using ss1.
    uint8_t m2[CRYPTO_BYTES] = {0};                                      // Recovered plaintext after decryption.

    /*
     * Fill the original message m1 with simple example values:
     * 01, 02, 03, ..., 20 in hexadecimal.
     * Since CRYPTO_BYTES = 32 for HQC-1, this creates a 32-byte message.
     */
    for (size_t i = 0; i < CRYPTO_BYTES; i++) {                          // Loop over all 32 positions.
        m1[i] = (uint8_t)(i + 1);                                        // Store values 1, 2, 3, ..., 32.
    }

    printf("PK bytes: %d\n", CRYPTO_PUBLICKEYBYTES);                     // Print public key size.
    printf("SK bytes: %d\n", CRYPTO_SECRETKEYBYTES);                     // Print secret key size.
    printf("CT bytes: %d\n", CRYPTO_CIPHERTEXTBYTES);                    // Print ciphertext size.
    printf("SS bytes: %d\n", CRYPTO_BYTES);                              // Print shared secret size.

    /*
     * Step 1: Generate HQC-KEM keypair.
     * pk will be the public key.
     * sk will be the secret key.
     */
    printf("Generating KEM keypair...\n");                               // Inform the user that key generation starts.
    if (crypto_kem_keypair(pk, sk) != 0) {                               // Call HQC keypair generation.
        printf("keypair failed\n");                                      // If something goes wrong, print error.
        return 1;                                                        // Exit with nonzero status to indicate failure.
    }

    /*
     * Step 2: Encapsulation.
     * Using the public key pk, create:
     *   - ct  = HQC ciphertext
     *   - ss1 = sender-side shared secret
     */
    printf("Encapsulating to get CT and SS1...\n");                      // Inform the user that encapsulation starts.
    if (crypto_kem_enc(ct, ss1, pk) != 0) {                              // Encapsulate using the public key.
        printf("encapsulation failed\n");                                // Print error if encapsulation fails.
        return 1;                                                        // Exit with failure status.
    }


    /*
     * Step 3: DEM encryption.
     * Here we encrypt the message m1 using the shared secret ss1.
     * We do this with bytewise XOR:
     *
     *   dem[i] = ss1[i] XOR m1[i]
     *
     * This creates the second part of the final ciphertext.
     */
    for (size_t i = 0; i < CRYPTO_BYTES; i++) {                          // Loop over all 32 bytes.
        dem[i] = ss1[i] ^ m1[i];                                         // XOR shared secret byte with message byte.
    }

    /*
     * At this point, the final hybrid ciphertext is conceptually:
     *
     *   C = (ct, dem)
     *
     * where:
     *   ct  = HQC KEM ciphertext
     *   dem = message encrypted with shared secret
     */

    /*
     * Step 4: Decapsulation.
     * Using ct and sk, the receiver recovers the shared secret ss2.
     * If the KEM works correctly, then ss2 should be identical to ss1.
     */
    printf("Decapsulating CT to recover SS2...\n");                      // Inform the user that decapsulation starts.
    if (crypto_kem_dec(ss2, ct, sk) != 0) {                              // Recover shared secret using ciphertext and secret key.
        printf("decapsulation failed\n");                                // Print error if decapsulation fails.
        return 1;                                                        // Exit with failure status.
    }

    /*
     * Step 5: DEM decryption.
     * Recover the original message using:
     *
     *   m2[i] = ss2[i] XOR dem[i]
     *
     * Since ideally ss2 = ss1, this becomes:
     *
     *   m2[i] = ss1[i] XOR (ss1[i] XOR m1[i]) = m1[i]
     *
     * because XOR with the same value cancels out.
     */
    for (size_t i = 0; i < CRYPTO_BYTES; i++) {                          // Loop over all 32 bytes again.
        m2[i] = ss2[i] ^ dem[i];                                         // XOR recovered shared secret with DEM to recover message.
    }

    print_hex("Original message m1", m1, CRYPTO_BYTES);                  // Print original plaintext in hex.
    print_hex("Recovered message m2", m2, CRYPTO_BYTES);                 // Print recovered plaintext in hex.

    /*
     * Step 6: Final verification.
     * Compare original message m1 with recovered message m2.
     * memcmp() compares byte-by-byte for CRYPTO_BYTES bytes.
     * If result is 0, they are exactly equal.
     */
    if (memcmp(m1, m2, CRYPTO_BYTES) == 0) {                             // Check whether both messages are identical.
        printf("SUCCESS: decrypted message matches original message\n");  // Print success if decryption worked correctly.
    } else {                                                             // Otherwise...
        printf("FAIL: decrypted message does not match original message\n"); // Print failure if messages differ.
    }

    return 0;                                                            // End program successfully.
}
