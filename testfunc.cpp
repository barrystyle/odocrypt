//! barrystyle 28012021

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <KeccakP-800-SnP.h>
#include <odocrypt.h>

#include <openssl/sha.h>

#include <chrono>

#define ITERATIONS 4096
#define CHAMBER_SIZE 262144

void OdocryptOldHash(const char* input, char* output, uint32_t key)
{
    char cipher[KeccakP800_stateSizeInBytes];
    memset(cipher, 0, sizeof(cipher));
    memcpy(cipher, input, 80);

    OdoCrypt odoHash(key);
    odoHash.Encrypt(cipher, cipher);
    KeccakP800_Permute_12rounds(cipher);
    memcpy(&output, cipher, 32);
}

void OdocryptNewHash(const char* input, char* output, uint32_t key)
{
    OdocryptOldHash(input, output, key);

    unsigned char *cur, *next;
    unsigned char chamber[CHAMBER_SIZE];
    memcpy(chamber, output, 32);
    for (unsigned int i = 0; i < (CHAMBER_SIZE / 32) - 32; i++) {
        cur = &chamber[i * 32];
        next = &chamber[(i + 1) * 32];
        SHA256(cur, 32, next);
    }
    SHA256(chamber, CHAMBER_SIZE, (unsigned char*)output);
}

int main()
{
    char input[80];
    char output[32];
    memset(input, 0xFF, 80);
    auto duration = std::chrono::system_clock::now().time_since_epoch();
    auto millis_st = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

    for (unsigned int i = 0; i < ITERATIONS; i++)
        OdocryptNewHash(input, output, 0);

    duration = std::chrono::system_clock::now().time_since_epoch();
    auto millis_fn = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    printf("%d hashes took %dms\n", ITERATIONS, millis_fn - millis_st);

    return 1;
}
