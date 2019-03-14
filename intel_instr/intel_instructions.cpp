#include <stdio.h>
#include <stdint.h>
#include <immintrin.h>

/* AES-128 simple implementation template and testing */

/*
Author: Aheyeu Anton, aheyeant@fit.cvut.cz
Template: Jiri Bucek 2017
AES specification:
http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
*/

/* AES Constants */

/* AES state type */
typedef uint32_t t_state[4];

inline uint8_t wbyte(uint32_t w, int pos) {
    return (w >> (pos * 8)) & 0xff;
}

void expandKey128(uint8_t k[16], __m128i ek[11]) {
    __m128i temp1;
    __m128i temp2;
    __m128i temp;
    int b = 0;
    ek[0] = _mm_loadu_si128((__m128i *) k);                 //b1

    temp1 = _mm_aeskeygenassist_si128(ek[b], 0x00000001);   //b2
    temp1 = _mm_shuffle_epi32(temp1, 0xff);
    temp2 = ek[b];
    temp = _mm_slli_si128 (ek[b] , 4);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 8);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 12);
    temp2 = _mm_xor_si128(temp2, temp);
    b++;                                //1
    ek[b] = _mm_xor_si128(temp1, temp2);

    temp1 = _mm_aeskeygenassist_si128(ek[b], 0x00000002);   //b3
    temp1 = _mm_shuffle_epi32(temp1, 0xff);
    temp2 = ek[b];
    temp = _mm_slli_si128 (ek[b] , 4);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 8);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 12);
    temp2 = _mm_xor_si128(temp2, temp);
    b++;                                //2
    ek[b] = _mm_xor_si128(temp1, temp2);

    temp1 = _mm_aeskeygenassist_si128(ek[b], 0x00000004);   //b4
    temp1 = _mm_shuffle_epi32(temp1, 0xff);
    temp2 = ek[b];
    temp = _mm_slli_si128 (ek[b] , 4);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 8);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 12);
    temp2 = _mm_xor_si128(temp2, temp);
    b++;                                //3
    ek[b] = _mm_xor_si128(temp1, temp2);

    temp1 = _mm_aeskeygenassist_si128(ek[b], 0x00000008);   //b5
    temp1 = _mm_shuffle_epi32(temp1, 0xff);
    temp2 = ek[b];
    temp = _mm_slli_si128 (ek[b] , 4);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 8);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 12);
    temp2 = _mm_xor_si128(temp2, temp);
    b++;                                //4
    ek[b] = _mm_xor_si128(temp1, temp2);

    temp1 = _mm_aeskeygenassist_si128(ek[b], 0x00000010);   //b6
    temp1 = _mm_shuffle_epi32(temp1, 0xff);
    temp2 = ek[b];
    temp = _mm_slli_si128 (ek[b] , 4);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 8);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 12);
    temp2 = _mm_xor_si128(temp2, temp);
    b++;                                //5
    ek[b] = _mm_xor_si128(temp1, temp2);

    temp1 = _mm_aeskeygenassist_si128(ek[b], 0x00000020);   //b7
    temp1 = _mm_shuffle_epi32(temp1, 0xff);
    temp2 = ek[b];
    temp = _mm_slli_si128 (ek[b] , 4);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 8);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 12);
    temp2 = _mm_xor_si128(temp2, temp);
    b++;                                //6
    ek[b] = _mm_xor_si128(temp1, temp2);

    temp1 = _mm_aeskeygenassist_si128(ek[b], 0x00000040);   //b8
    temp1 = _mm_shuffle_epi32(temp1, 0xff);
    temp2 = ek[b];
    temp = _mm_slli_si128 (ek[b] , 4);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 8);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 12);
    temp2 = _mm_xor_si128(temp2, temp);
    b++;                                //7
    ek[b] = _mm_xor_si128(temp1, temp2);

    temp1 = _mm_aeskeygenassist_si128(ek[b], 0x00000080);   //b9
    temp1 = _mm_shuffle_epi32(temp1, 0xff);
    temp2 = ek[b];
    temp = _mm_slli_si128 (ek[b] , 4);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 8);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 12);
    temp2 = _mm_xor_si128(temp2, temp);
    b++;                                //8
    ek[b] = _mm_xor_si128(temp1, temp2);

    temp1 = _mm_aeskeygenassist_si128(ek[b], 0x0000001b);   //b10
    temp1 = _mm_shuffle_epi32(temp1, 0xff);
    temp2 = ek[b];
    temp = _mm_slli_si128 (ek[b] , 4);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 8);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 12);
    temp2 = _mm_xor_si128(temp2, temp);
    b++;                                //9
    ek[b] = _mm_xor_si128(temp1, temp2);

    temp1 = _mm_aeskeygenassist_si128(ek[b], 0x00000036);   //b11
    temp1 = _mm_shuffle_epi32(temp1, 0xff);
    temp2 = ek[b];
    temp = _mm_slli_si128 (ek[b] , 4);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 8);
    temp2 = _mm_xor_si128(temp2, temp);
    temp = _mm_slli_si128 (ek[b] , 12);
    temp2 = _mm_xor_si128(temp2, temp);
    b++;                                //10
    ek[b] = _mm_xor_si128(temp1, temp2);
}

void aes(uint8_t *in, uint8_t *out, uint8_t *skey) {
    //... Initialize ...
    //unsigned short round = 0;
    t_state state;
    __m128i ST;
    __m128i eKey128 [11];

    ST = _mm_loadu_si128((__m128i *) in);
    expandKey128(skey, eKey128);
    ST = _mm_xor_si128(ST, eKey128[0]);
    for (int i = 1; i < 10; i++) {
        ST = _mm_aesenc_si128(ST, eKey128[i]);
    }
    ST = _mm_aesenclast_si128(ST, eKey128[10]);
    _mm_storeu_si128((__m128i *) &state, ST);
    for (int i = 0; i < 16; i++) {
        if (i < 4) out[i] = wbyte(state[0], i % 4);
        else if (i < 8) out[i] = wbyte(state[1], i % 4);
        else if (i < 12) out[i] = wbyte(state[2], i % 4);
        else out[i] = wbyte(state[3], i % 4);
    }
}

//****************************
// MAIN function: AES testing
//****************************
int main(int argc, char* argv[]) {
    uint8_t key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    uint8_t iv[16]  = { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 };

    uint8_t PT[16]  = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    uint8_t res[16] = { 0xa3, 0x3a, 0xca, 0x68, 0x72, 0xa2, 0x27, 0x74, 0xbf, 0x99, 0xf3, 0x71, 0xaa, 0x99, 0xd2, 0x5a };

    uint8_t outEK[16];
    unsigned long int loop_max = 1000000;

    if (argc > 1) {
        loop_max = 0;
        int i = 0;
        while (i < 19) {
            if (argv[1][i] == '\0') {
                break;
            } else {
                loop_max += (unsigned long int)(((int)argv[1][i++]) - 48);
                loop_max *= 10;
            }
        }
        loop_max /= 10;

    }
    //start AES
    aes(iv, outEK, key);
    for (unsigned long int i = 0; i < loop_max; i++) {
        aes(outEK, outEK, key);
        for (int ii = 0; ii < 16; ii++) {
            res[ii] = outEK[ii] ^ PT[ii];
        }
    }
    //stop AES
    return res[0];
}