# CifraTeste-1024: O Desafio Criptográfico

## Categorias: Criptoanálise | Cipher Design | SPN Block Cipher

**Dificuldade:** ★★★☆☆ (Médio)  
**Autor:** Euzebio Santos  
**Tags:** `spn`, `sbox-aes`, `gf28`, `mds`, `blake3-cvb`

---

## Visão Geral

CifraTeste-1024 é uma **cifra de bloco SPN (Substitution-Permutation Network)** com:
- **Bloco:** 1024 bits (128 bytes)
- **Chave:** 256 bits (32 bytes)
- **Rodadas:** 16

Componentes:
- **SubBytes:** S-box de 8 bits (AES) — não-linearidade máxima (112)
- **ShiftRows:** Rotação por linha (32 colunas × 4 bytes)
- **MixColumns:** Matriz MDS [2,3,1,1] em GF(2⁸) — irreduzível x⁸+x⁴+x³+x+1
- **AddRoundKey:** XOR com subchave
- **Key Schedule:** Blake3-inspired CVB (Chained Value Block) com ARX mixing

## Arquivos Fornecidos

```
cifrateste1024.h    - Header da implementação (público)
cifrateste1024.c    - Implementação completa (público)
challenge.c         - Servidor do desafio (público)
```

## Desafios

### Level 1 (Básico) — "Chave Pública"

**Ciphertext (chave = 0000...0000):**
```
f407acdbaa6ac384d1a954476901a9eb5aa16b3625de96b907cbfc47448c979d910909ee420b4bfe9b67b863321a824f5b7ad7186e4fe82015150c8850782931680097a067cf44981dad5e19e3d060931bced74339a39acefd4d35874d8fd95f74a5fe7a75aa187a0aa3aeae0305e5708015299dca504cf91847c49dce9b7bca
```

**Dica:** A chave de cifragem é **pública** e está documentada. Qual é ela?

**Pergunta:** Qual é a flag?

---

### Level 2 (Médio) — "Invertendo o CVB"

**Ciphertext (chave secreta):**
```
0b5e1fefc3345179a00be0863035af763b1e8870b4c1ef8011af0d6bb43f395f0cbee5e110eeaafa1e240f568051cf98590f9bb3db7c04e8e6f36692dbcda5babed4023f966cf917620667d2e33f8c73c01197427c5e3127b2106ff0f28aa9785cb96f3ce05e0b9e372c800bd9e6d35dc2bbc11e4195fcd94cf5e561bb43cdc4
```

**Dica — Última subchave (Round Key #15):**
```
c7581a5945ba5383a7ec47ab7ef10a565269ad9e1aaec71071dc80ec866ddadbb533e974ca0f5b190748c9a689f117bf545ceae015eebc59ca6ccdd4e25d44390acdeb9d72ff6ce1b7c7acc9673bfc8bdadef480dca60d3d38e08d501c7d4e1e6169b1f0be89eba5391f656883caaab41cf4a664d17371fa90aa94b660418b88
```

**Pergunta:** Se você tem a última subchave e conhece a estrutura do key schedule CVB, é possível recuperar a chave mestra. Qual é a flag?

---

### Level 3 (Expert) — "XOR Linear"

**Ciphertext (nonce XOR + chave secreta):**
```
c731dbd64f46230e2236bda9965ba141226fe012551baffda38400ac3fb2d0a062b4c7fddb854b10064717896812f0a3980b2ab7991ff6c4a816ec39793c86a3a2b3639cdc6fdf979b0d7071bab544d617b9b17ea2c05e81e2abb12d8238f246a5ab30ef98477f1b10339e5304aa2c9944acb44e25401c19eec298179da38e54
```

**Nonce (fornecido):**
```
41424344454647483132333435363738deadbeefcafebabe0123456789abcdef
```

**Dica:** O plaintext foi XOR-combinado com o nonce **antes** da cifragem. A chave é a mesma do Level 2. O MixColumns é uma operação **linear** sobre o estado. O que isso implica sobre a relação entre ciphertexts com chaves diferentes?

**Pergunta:** Qual é a flag?

---

## Dados para Análise Estatística

### Chave Pública (0000...0000)

16 pares plaintext-ciphertext:

| # | PT (hex) | CT (primeiros 16 bytes) |
|---|----------|------------------------|
| 0 | `0000000000000000` | `dbc610d3fadd29b2` |
| 1 | `0000000000000001` | `b7fe60de29e42b9f` |
| 2 | `0000000000000002` | `d5cf7c715d907b05` |
| 3 | `0000000000000003` | `8be1488558538f4b` |
| 4 | `0000000000000004` | `d78e8469c6824799` |
| 5 | `0000000000000005` | `3b610f56407e5fb9` |
| 6 | `0000000000000006` | `64d9fc6d837537e4` |
| 7 | `0000000000000007` | `e360aeccbea0818c` |
| 8 | `0000000000000008` | `e8b0a09d3b708815` |
| 9 | `0000000000000009` | `8d78b739930ff826` |
| 10 | `000000000000000a` | `8f865e154925baf7` |
| 11 | `000000000000000b` | `1c3fd0e8aa5c858b` |
| 12 | `000000000000000c` | `f5b97cbc25c1ee23` |
| 13 | `000000000000000d` | `8d98f388fe5a9272` |
| 14 | `000000000000000e` | `81323941a9ec6f2c` |
| 15 | `000000000000000f` | `c63fcfa1e6db4932` |

### Chave Secreta

16 pares plaintext-ciphertext:

| # | PT (hex) | CT (primeiros 16 bytes) |
|---|----------|------------------------|
| 0 | `0000000000000000` | `79e04e55d3f24a32` |
| 1 | `0000000000000001` | `96ee30124f5b9f6d` |
| 2 | `0000000000000002` | `aaec123e4c349b5d` |
| 3 | `0000000000000003` | `4b19de931e577967` |
| 4 | `0000000000000004` | `6b508ec31e1a1118` |
| 5 | `0000000000000005` | `5416a8788ada9577` |
| 6 | `0000000000000006` | `fe1f6114227032f9` |
| 7 | `0000000000000007` | `85666ffa0533ac3c` |
| 8 | `0000000000000008` | `f0fd480a33b875bd` |
| 9 | `0000000000000009` | `ea9094f8d0452701` |
| 10 | `000000000000000a` | `3d0b031481511a52` |
| 11 | `000000000000000b` | `4170303b92ef253a` |
| 12 | `000000000000000c` | `323338a5b96c6e0f` |
| 13 | `000000000000000d` | `8cbc3d95e0208010` |
| 14 | `000000000000000e` | `ebacb33991d845b1` |
| 15 | `000000000000000f` | `1f93959681d77dcd` |

### S-box

```
63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
04 c7 23 c3 18 96 05 9a 07 12 80 eb 27 b2 75 09
83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84 53
d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf d0
ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8 51
a3 40 8f 92 9d 38 f5 bc b6 da 21 10 fF f3 d2 cd
0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73 60
81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db e0
32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79 e7
c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08 ba
78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a 70
3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e e1
f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df 8c
a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
```

### S-box Inversa

```
52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb
7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb
54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e
08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25
72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92
6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84
90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06
d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b
3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73
96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e
47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b
fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4
1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f
60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef
a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61
17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d
```

---

## Formato da Resposta

Todas as flags seguem o formato: `FLAG{...}`

**Level 1:** `FLAG{...}`  
**Level 2:** `FLAG{...}`  
**Level 3:** `FLAG{...}`

---

## Pistas (liberadas após 24h)

### Pista 1 — Level 1
> Qual é a chave de cifragem usada no Level 1? Ela está documentada no desafio. Se a chave é conhecida, qual operação você precisa fazer para reverter a cifragem?

### Pista 2 — Level 2
> O key schedule CVB funciona assim: `round_key[i] = compress(master_key, round_constants[i])`. Se você tem `round_key[15]` e conhece `round_constants[15]`, pode tentar inverter a compressão. A compressão CVB usa operações ARX (Add-Rotate-XOR) — essas são reversíveis.

### Pista 3 — Level 3
> O MixColumns é uma operação **linear**: `Mix(a ⊕ b) = Mix(a) ⊕ Mix(b)`. Se você sabe que `Encrypt(K, P) = C` e `Encrypt(K, P') = C'`, o que pode dizer sobre `Encrypt(K, P ⊕ P')`?

---

## Propriedades Criptográficas

### Análise Diferencial
- S-box máxima probabilidade diferencial: 4/256 = 1.56%
- Propagação diferencial: ~50% dos bits após 2 rodadas
- Segurança estimada: ~96 bits contra ataques diferenciais

### Análise Linear
- Melhor bias linear: 12.50%
- Segurança estimada: ~48 bits contra ataques lineares puros

### Difusão
- 1 rodada: 506/1024 bits (49.4%)
- 2 rodadas: 529/1024 bits (51.7%)
- 4 rodadas: 507/1024 bits (49.5%)

---

## Sobre a Cifra

CifraTeste-1024 é uma cifra SPN de pesquisa que combina:
- **S-box de AES:** Não-linearidade máxima para S-boxes de 8 bits
- **Matriz MDS:** Difusão máxima por coluna (prova de mínima distância de distância)
- **Key schedule Blake3:** Construção moderna e robusta
- **Bloco grande (1024 bits):** Resistência a ataques de bloco grande

O desafio testa understanding da estrutura SPN, propriedades lineares, e capacidade de inverter funções criptográficas.

**Boa sorte!**
