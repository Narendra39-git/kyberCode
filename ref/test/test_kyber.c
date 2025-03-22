#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
// #include "crypto_kem.h"
#include "randombytes.h"
#include "aes.h" // Include your AES implementation header

#define MESSAGE "IIT Jammu"
#define MESSAGE_LEN 10 // Length of the message
#define NTESTS 1 // Number of tests to run

static int test_keys(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];
    uint8_t encrypted_message[MESSAGE_LEN];
    uint8_t decrypted_message[MESSAGE_LEN];

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

    // Encrypt the message using AES with the generated key
    aes_encrypt(key_b, MESSAGE, encrypted_message, MESSAGE_LEN);

    // Measure Decapsulation Time
    start = clock();
    crypto_kem_dec(key_a, ct, sk);
    end = clock();
    dec_time = (double)(end - start) / CLOCKS_PER_SEC;

    // Decrypt the message using AES with the decapsulated key
    aes_decrypt(key_a, encrypted_message, decrypted_message, MESSAGE_LEN);

    if (memcmp(key_a, key_b, CRYPTO_BYTES)) {
        printf("ERROR keys\n");
        return 1;
    }

    printf("KeyGen Time: %f sec | Enc Time: %f sec | Dec Time: %f sec\n", keygen_time, enc_time, dec_time);
    printf("Original Message: %s\n", MESSAGE);
    printf("Encrypted Message: ");
    for (int i = 0; i < MESSAGE_LEN; i++) {
        printf("%02x", encrypted_message[i]);
    }
    printf("\n");
    printf("Decrypted Message: %s\n", decrypted_message);

    return 0;
}

int main(void)
{
    int r;

    printf("Running %d test...\n", NTESTS);

    r = test_keys();
    if (r) return 1;

    return 0;
}
