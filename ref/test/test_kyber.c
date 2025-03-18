#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../kem.h"
#include "../randombytes.h"
#include <time.h>

#define NTESTS 1000

static int test_keys(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];

    clock_t start, end;
    double keygen_time, enc_time, dec_time;

    // Measure Key Generation Time
    start = clock();
    crypto_kem_keypair(pk, sk);
    end = clock();
    keygen_time = (double)(end - start) / CLOCKS_PER_SEC;

    // Measure Encapsulation Time
    start = clock();
    crypto_kem_enc(ct, key_b, pk);
    end = clock();
    enc_time = (double)(end - start) / CLOCKS_PER_SEC;

    // Measure Decapsulation Time
    start = clock();
    crypto_kem_dec(key_a, ct, sk);
    end = clock();
    dec_time = (double)(end - start) / CLOCKS_PER_SEC;

    if (memcmp(key_a, key_b, CRYPTO_BYTES)) {
        printf("ERROR keys\n");
        return 1;
    }

    printf("KeyGen Time: %f sec | Enc Time: %f sec | Dec Time: %f sec\n", keygen_time, enc_time, dec_time);

    return keygen_time, enc_time, dec_time;
}

int main(void)
{
    unsigned int i;
    int r;

    double total_keygen_time = 0.0;
    double total_enc_time = 0.0;
    double total_dec_time = 0.0;

    printf("Running %d tests...\n", NTESTS);
    
    for (i = 0; i < NTESTS; i++) {
        r = test_keys();
        if (r) return 1;
    }

    // Calculate total time for all tests
    total_keygen_time += keygen_time;
    total_enc_time += enc_time;
    total_dec_time += dec_time;

    // Calculate average time for each operation
    double avg_keygen_time = total_keygen_time / NTESTS;
    double avg_enc_time = total_enc_time / NTESTS;
    double avg_dec_time = total_dec_time / NTESTS;

    // Print the total and average times
    printf("\nTotal time for %d tests:\n", NTESTS);
    printf("Total KeyGen Time: %f sec\n", total_keygen_time);
    printf("Total Encapsulation Time: %f sec\n", total_enc_time);
    printf("Total Decapsulation Time: %f sec\n", total_dec_time);

    printf("\nAverage time per operation:\n");
    printf("Average KeyGen Time: %f sec\n", avg_keygen_time);
    printf("Average Encapsulation Time: %f sec\n", avg_enc_time);
    printf("Average Decapsulation Time: %f sec\n", avg_dec_time);

    printf("CRYPTO_SECRETKEYBYTES:  %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_PUBLICKEYBYTES:  %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_CIPHERTEXTBYTES: %d\n", CRYPTO_CIPHERTEXTBYTES);

    return 0;
}
