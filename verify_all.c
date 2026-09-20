#define SPECTRUM_NO_MAIN
#include "spectrum1024.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    uint64_t key[4] = {
        0xa3f1d829c04b6e57ULL, 0x71b2e4f09d853a6cULL,
        0xd5e90f3a816724beULL, 0x3c84a716f2db59e0ULL
    };
    uint64_t nonce[4] = {0x4142434445464748ULL, 0x3132333435363738ULL,
                         0xdeadbeefcafebabeULL, 0x0123456789abcdefULL};
    
    /* Encrypt flag3: PT XOR nonce, then encrypt */
    const char *flag3 = "FLAG{carry_killers_quebram_a_difusao_linear}";
    uint64_t ct[16] = {0};
    size_t len = strlen(flag3);
    memcpy(ct, flag3, len);
    uint8_t *bytes = (uint8_t *)ct;
    uint8_t pad = (uint8_t)(128 - len);
    for (size_t i = len; i < 128; i++) bytes[i] = pad;
    for (int i = 0; i < 4; i++) ct[i] ^= nonce[i];
    spectrum_encrypt(ct, key);
    
    /* Known ciphertext */
    uint64_t known[16] = {
        0x805d2b43e59252d0ULL, 0x31c6e2e256ef4e4eULL,
        0x15f453b171ebd02aULL, 0x506176fd8be6bca9ULL,
        0x79ec4238e8a4f225ULL, 0x45ab25a71f8dd215ULL,
        0x080a16dc6c66966aULL, 0xbd31b4202f6b282dULL,
        0x12f4b740d4f9ff42ULL, 0x3d57d02d80460b5bULL,
        0xa098f54a479f20c7ULL, 0x89b8b26a9dc2aa31ULL,
        0x41147773028ef2dfULL, 0x5097279e6e0a3a77ULL,
        0xb775511e351e5046ULL, 0x27cdd33235bc2f44ULL
    };
    
    printf("Level 3 verification:\n");
    printf("Computed: ");
    for (int i = 0; i < 16; i++) printf("%016llx", (unsigned long long)ct[i]);
    printf("\nKnown:    ");
    for (int i = 0; i < 16; i++) printf("%016llx", (unsigned long long)known[i]);
    printf("\nMatch: %s\n", memcmp(ct, known, 128) == 0 ? "YES" : "NO");
    
    /* Decrypt and XOR */
    uint64_t pt[16];
    memcpy(pt, known, 128);
    spectrum_decrypt(pt, key);
    for (int i = 0; i < 4; i++) pt[i] ^= nonce[i];
    
    char *text = (char *)pt;
    int text_len = len;
    printf("Decrypted: %.*s\n", text_len, text);
    
    return 0;
}
