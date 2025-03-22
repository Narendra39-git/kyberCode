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

    // Check if the keys match
    if (memcmp(key_a, key_b, CRYPTO_BYTES)) {
        printf("ERROR keys\n");
        return 1;
    }

    // Print timing information
    printf("KeyGen Time: %f sec | Enc Time: %f sec | Dec Time: %f sec\n", keygen_time, enc_time, dec_time);

    // Print the ciphertext and shared secret key
    printf("Ciphertext: ");
    for (size_t i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) {
        printf("%02x", ct[i]);
    }
    printf("\n");

    printf("Decapsulated Key (Plaintext): ");
    for (size_t i = 0; i < CRYPTO_BYTES; i++) {
        printf("%02x", key_a[i]);
    }
    printf("\n");

    return 0;
}

int main(void)
{
    unsigned int i;
    int r;

    printf("Running %d tests...\n", NTESTS);
    
    for (i = 0; i < NTESTS; i++) {
        r = test_keys();
        if (r) return 1;
    }

    printf("CRYPTO_SECRETKEYBYTES:  %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_PUBLICKEYBYTES:  %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_CIPHERTEXTBYTES: %d\n", CRYPTO_CIPHERTEXTBYTES);

    return 0;
}
