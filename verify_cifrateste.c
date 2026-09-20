#define CT_NO_MAIN 1
#include "cifrateste1024.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    uint64_t key[4] = {
        0xdeadbeefcafebabeULL, 0x0123456789abcdefULL,
        0xfedcba9876543210ULL, 0x0011223344556677ULL
    };
    uint64_t nonce[4] = {0x4142434445464748ULL, 0x3132333435363738ULL,
                         0xdeadbeefcafebabeULL, 0x0123456789abcdefULL};

    printf("=== VERIFICACAO COMPLETA DO DESAFIO CIFRATESTE-1024 ===\n\n");

    /* Level 1: Chave publica = 0 */
    printf("[Level 1] Verificando com chave publica (0)...\n");
    const char *flag1 = "FLAG{cifrateste_spn_eh_um_bom_exemplo_de_cifra_de_bloco}";
    uint64_t state1[16] = {0};
    size_t len1 = strlen(flag1);
    memcpy(state1, flag1, len1);
    uint8_t *bytes1 = (uint8_t *)state1;
    uint8_t pad1 = (uint8_t)(128 - len1);
    for (size_t i = len1; i < 128; i++) bytes1[i] = pad1;
    ct_encrypt(state1, (uint64_t[4]){0});

    uint64_t known1[16] = {
        0xf407acdbaa6ac384ULL, 0xd1a954476901a9ebULL,
        0x5aa16b3625de96b9ULL, 0x07cbfc47448c979dULL,
        0x910909ee420b4bfeULL, 0x9b67b863321a824fULL,
        0x5b7ad7186e4fe820ULL, 0x15150c8850782931ULL,
        0x680097a067cf4498ULL, 0x1dad5e19e3d06093ULL,
        0x1bced74339a39aceULL, 0xfd4d35874d8fd95fULL,
        0x74a5fe7a75aa187aULL, 0x0aa3aeae0305e570ULL,
        0x8015299dca504cf9ULL, 0x1847c49dce9b7bcaULL
    };
    printf("  Computado: ");
    for (int i = 0; i < 16; i++) printf("%016llx", (unsigned long long)state1[i]);
    printf("\n  Esperado:  ");
    for (int i = 0; i < 16; i++) printf("%016llx", (unsigned long long)known1[i]);
    printf("\n  Match: %s\n\n", memcmp(state1, known1, 128) == 0 ? "SIM" : "NAO");

    /* Level 2: Chave secreta */
    printf("[Level 2] Verificando com chave secreta...\n");
    const char *flag2 = "FLAG{key_schedule_cvb_pode_ser_invertido_se_voce_sabe_um_round_key}";
    uint64_t state2[16] = {0};
    size_t len2 = strlen(flag2);
    memcpy(state2, flag2, len2);
    uint8_t *bytes2 = (uint8_t *)state2;
    uint8_t pad2 = (uint8_t)(128 - len2);
    for (size_t i = len2; i < 128; i++) bytes2[i] = pad2;
    ct_encrypt(state2, key);

    uint64_t known2[16] = {
        0x0b5e1fefc3345179ULL, 0xa00be0863035af76ULL,
        0x3b1e8870b4c1ef80ULL, 0x11af0d6bb43f395fULL,
        0x0cbee5e110eeaafaULL, 0x1e240f568051cf98ULL,
        0x590f9bb3db7c04e8ULL, 0xe6f36692dbcda5ba,
        0xbed4023f966cf917ULL, 0x620667d2e33f8c73ULL,
        0xc01197427c5e3127ULL, 0xb2106ff0f28aa978ULL,
        0x5cb96f3ce05e0b9eULL, 0x372c800bd9e6d35dULL,
        0xc2bbc11e4195fcd9ULL, 0x4cf5e561bb43cdc4ULL
    };
    printf("  Computado: ");
    for (int i = 0; i < 16; i++) printf("%016llx", (unsigned long long)state2[i]);
    printf("\n  Esperado:  ");
    for (int i = 0; i < 16; i++) printf("%016llx", (unsigned long long)known2[i]);
    printf("\n  Match: %s\n\n", memcmp(state2, known2, 128) == 0 ? "SIM" : "NAO");

    /* Level 3: XOR nonce + chave secreta */
    printf("[Level 3] Verificando XOR nonce + chave secreta...\n");
    const char *flag3 = "FLAG{gf28_mix_columns_e_um_operador_linear_sobre_o_estado}";
    uint64_t state3[16] = {0};
    size_t len3 = strlen(flag3);
    memcpy(state3, flag3, len3);
    uint8_t *bytes3 = (uint8_t *)state3;
    uint8_t pad3 = (uint8_t)(128 - len3);
    for (size_t i = len3; i < 128; i++) bytes3[i] = pad3;
    for (int i = 0; i < 4; i++) state3[i] ^= nonce[i];
    ct_encrypt(state3, key);

    uint64_t known3[16] = {
        0xc731dbd64f46230eULL, 0x2236bda9965ba141ULL,
        0x226fe012551baffdULL, 0xa38400ac3fb2d0a0ULL,
        0x62b4c7fddb854b10ULL, 0x064717896812f0a3ULL,
        0x980b2ab7991ff6c4ULL, 0xa816ec39793c86a3ULL,
        0xa2b3639cdc6fdf97ULL, 0x9b0d7071bab544d6ULL,
        0x17b9b17ea2c05e81ULL, 0xe2abb12d8238f246ULL,
        0xa5ab30ef98477f1bULL, 0x10339e5304aa2c99ULL,
        0x44acb44e25401c19ULL, 0xeec298179da38e54ULL
    };
    printf("  Computado: ");
    for (int i = 0; i < 16; i++) printf("%016llx", (unsigned long long)state3[i]);
    printf("\n  Esperado:  ");
    for (int i = 0; i < 16; i++) printf("%016llx", (unsigned long long)known3[i]);
    printf("\n  Match: %s\n\n", memcmp(state3, known3, 128) == 0 ? "SIM" : "NAO");

    /* Decrypt round-trip */
    printf("[Round-trip] Verificando encrypt->decrypt...\n");
    uint64_t test[16] = {0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL};
    uint64_t orig[16];
    memcpy(orig, test, 128);
    ct_encrypt(test, key);
    ct_decrypt(test, key);
    printf("  Round-trip: %s\n\n", memcmp(test, orig, 128) == 0 ? "SIM" : "NAO");

    printf("=== VERIFICACAO COMPLETA ===\n");
    return 0;
}
