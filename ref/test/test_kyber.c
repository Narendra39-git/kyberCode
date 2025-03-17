#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>  // Include time.h for timing functions
#include "../kem.h"
#include "../randombytes.h"

#define NTESTS 1000

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];

    clock_t start, end;
    double total_keygen_time = 0.0, total_enc_time = 0.0, total_dec_time = 0.0;

    printf("Running %d tests...\n", NTESTS);

    for (unsigned int i = 0; i < NTESTS; i++) {
        // Measure Key Generation Time
        start = clock();
        crypto_kem_keypair(pk, sk);
        end = clock();
        total_keygen_time += (double)(end - start) / CLOCKS_PER_SEC;

        // Measure Encapsulation Time
        start = clock();
        crypto_kem_enc(ct, key_b, pk);
        end = clock();
        total_enc_time += (double)(end - start) / CLOCKS_PER_SEC;

        // Measure Decapsulation Time
        start = clock();
        crypto_kem_dec(key_a, ct, sk);
        end = clock();
        total_dec_time += (double)(end - start) / CLOCKS_PER_SEC;

        // Verify that both keys match
        if (memcmp(key_a, key_b, CRYPTO_BYTES)) {
            printf("ERROR: Keys do not match!\n");
            return 1;
        }
    }

    // Print average execution times
    printf("Average KeyGen Time: %f sec\n", total_keygen_time / NTESTS);
    printf("Average Encapsulation Time: %f sec\n", total_enc_time / NTESTS);
    printf("Average Decapsulation Time: %f sec\n", total_dec_time / NTESTS);

    // Print cryptographic parameter sizes
    printf("CRYPTO_SECRETKEYBYTES:  %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_PUBLICKEYBYTES:  %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_CIPHERTEXTBYTES: %d\n", CRYPTO_CIPHERTEXTBYTES);

    return 0;
}
