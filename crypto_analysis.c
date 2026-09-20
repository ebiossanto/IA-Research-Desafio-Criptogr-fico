#define CT_NO_MAIN 1
#include "cifrateste1024.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Differential Distribution Table for the S-box */
static int ddt[256][256];
static void compute_ddt(void) {
    memset(ddt, 0, sizeof(ddt));
    const uint8_t *sb = ct_get_sbox();
    for (int dx = 0; dx < 256; dx++)
        for (int x = 0; x < 256; x++)
            ddt[dx][sb[x] ^ sb[x ^ dx]]++;
}

/* Linear Approximation Table */
static int lat[256][256];
static int parity8(uint8_t x) {
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return x & 1;
}
static void compute_lat(void) {
    memset(lat, 0, sizeof(lat));
    const uint8_t *sb = ct_get_sbox();
    for (int a = 0; a < 256; a++)
        for (int b = 0; b < 256; b++) {
            int sum = 0;
            for (int x = 0; x < 256; x++)
                sum += (parity8(a & x) == parity8(b & sb[x])) ? 1 : -1;
            lat[a][b] = sum;
        }
}

/* Count bits in a uint64_t */
static int popcount64(uint64_t x) {
    int c = 0;
    while (x) { c++; x &= x - 1; }
    return c;
}

/* Differential analysis: for each input difference, find best output difference */
static void differential_analysis(void) {
    printf("=== ANALISE DIFERENCIAL ===\n\n");
    compute_ddt();

    /* Find max DDT entry (excluding trivial dx=0, dy=0) */
    int max_ddt = 0;
    int best_dx = 0, best_dy = 0;
    for (int dx = 1; dx < 256; dx++)
        for (int dy = 0; dy < 256; dy++)
            if (ddt[dx][dy] > max_ddt) {
                max_ddt = ddt[dx][dy];
                best_dx = dx;
                best_dy = dy;
            }
    printf("Melhor caracteristica diferencial (1 rodada):\n");
    printf("  dx=0x%02x -> dy=0x%02x: probabilidade = %d/256 = %.2f%%\n",
           best_dx, best_dy, max_ddt, max_ddt * 100.0 / 256.0);

    /* Uniform distribution reference */
    printf("  Distribuicao uniforme: 1/256 = 0.39%%\n");
    printf("  Maximo possivel: 4/256 = 1.56%% (para S-box AES)\n\n");

    /* Avalanche de diferencial para multiplas rodadas */
    printf("Analise de propagacao diferencial:\n");
    uint64_t key[4] = {0};
    for (int dx_word = 1; dx_word < 256 && dx_word < 16; dx_word++) {
        for (int nrounds = 1; nrounds <= 16; nrounds++) {
            uint64_t pt1[16] = {0};
            uint64_t pt2[16] = {0};
            pt2[0] = (uint64_t)dx_word;
            for (int r = 0; r < nrounds; r++) {
                ct_encrypt(pt1, key);
                ct_encrypt(pt2, key);
            }
            int diff = 0;
            for (int i = 0; i < 16; i++)
                diff += popcount64(pt1[i] ^ pt2[i]);
            if (nrounds <= 4 || nrounds == 8 || nrounds == 12 || nrounds == 16)
                printf("  dx=0x%02x, %2d rodadas: %d/1024 bits (%.1f%%)\n",
                       dx_word, nrounds, diff, diff * 100.0 / 1024.0);
        }
    }
}

/* Linear analysis */
static void linear_analysis(void) {
    printf("\n=== ANALISE LINEAR ===\n\n");
    compute_lat();

    /* Find max LAT entry (excluding trivial a=0 or b=0) */
    int max_lat = 0;
    int best_a = 0, best_b = 0;
    for (int a = 1; a < 256; a++)
        for (int b = 1; b < 256; b++) {
            int abs_val = lat[a][b] < 0 ? -lat[a][b] : lat[a][b];
            if (abs_val > max_lat) {
                max_lat = abs_val;
                best_a = a;
                best_b = b;
            }
        }
    printf("Melhor aproximacao linear (1 rodada):\n");
    printf("  Entrada mascara a=0x%02x, Saida mascara b=0x%02x\n", best_a, best_b);
    printf("  Correlacao = %d/256 = %.2f%%\n", lat[best_a][best_b], lat[best_a][best_b] * 100.0 / 256.0);
    printf("  Bias = %.4f%%\n\n", (lat[best_a][best_b] * 100.0 / 256.0));

    /* Bias distribution */
    int hist[129] = {0};
    for (int a = 1; a < 256; a++)
        for (int b = 1; b < 256; b++) {
            int abs_val = lat[a][b] < 0 ? -lat[a][b] : lat[a][b];
            hist[abs_val]++;
        }
    printf("Distribuicao de bias no LAT:\n");
    for (int i = 128; i >= 4; i--)
        if (hist[i] > 0)
            printf("  |correlacao|=%d: %d pares\n", i, hist[i]);
}

int main(void) {
    printf("============================================\n");
    printf("  CifraTeste-1024: Analise Criptografica\n");
    printf("============================================\n\n");
    differential_analysis();
    linear_analysis();
    return 0;
}
