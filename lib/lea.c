#include <stdlib.h>
#include <string.h>
#include "./../include/crypto/lea.h"
#include "./../include/util.h"

const uint32_t delta[8] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
};

void LEA_encrypt(uint8_t * output, uint8_t * input, uint8_t * key_8, unsigned int key_len)
{
    lea_context context;
    uint32_t X[4] = { 0x00, };
    uint32_t key[8];
    unsigned int nr, nk;
    unsigned int i;
                        // unsigned int j;
    LEA_init(&context);
    context.key_len = key_len;

    // uint8_to_uint32(key, key_8, key_len);
    uint8_to_uint32_reverse_order(key, key_8, key_len);
    LEA_enc_key_schedule(&context, key);

    // X0 <- P
    // uint8_to_uint32(X, input, LEA_BLOCK_SIZE);
    uint8_to_uint32_reverse_order(X, input, LEA_BLOCK_SIZE);

    // for i = 0 to (Nr-1) do
    //     Xi+1 <- LEA.EncRound(Xi,RKienc)
    // end for
    nr = 16 + (key_len / 2);
    for (i = 0; i < nr; ++i)
    {
        LEA_enc_round(X, context.round_key[i]);
                    // printf("X[%d]=\t", i);
                    // for (j = 0; j < LEA_BLOCK_SIZE / 4; ++j) printf("%08X ", X[j]);
                    // printf("\n");
    }

    // C <- XNr
    // uint32_to_uint8(output, X, LEA_BLOCK_SIZE);
    uint32_to_uint8_reverse_order(output, X, LEA_BLOCK_SIZE);
}

void LEA_decrypt(uint8_t * output, uint8_t * input, uint8_t * key_8, unsigned int key_len)
{
    lea_context context;
    uint32_t X[4] = { 0x00, };
    uint32_t key[8];
    unsigned int nr, nk;
    unsigned int i;
                        unsigned int j;
    LEA_init(&context);
    context.key_len = key_len;

    // uint8_to_uint32(key, key_8, key_len);
    uint8_to_uint32_reverse_order(key, key_8, key_len);
    LEA_dec_key_schedule(&context, key);

    // X0 <- C
    // uint8_to_uint32(X, input, LEA_BLOCK_SIZE);
    uint8_to_uint32_reverse_order(X, input, LEA_BLOCK_SIZE);

    // for i = 0 to (Nr-1) do
    //     Xi+1 <- LEA.DecRound(Xi,RKienc)
    // end for
    nr = 16 + (key_len / 2);
    for (i = 0; i < nr; ++i)
    {
        LEA_dec_round(X, context.round_key[i]);
                    // printf("X[%d]=\t", i);
                    // for (j = 0; j < LEA_BLOCK_SIZE / 4; ++j) printf("%08X ", X[j]);
                    // printf("\n");
    }

    // P <- XNr
    // uint32_to_uint8(output, X, LEA_BLOCK_SIZE);
    uint32_to_uint8_reverse_order(output, X, LEA_BLOCK_SIZE);
}

void LEA_init(lea_context * context)
{
    memset(context, 0, sizeof(lea_context));
}

void LEA_enc_key_schedule(lea_context * context, uint32_t * key)
{
    uint32_t X[8] = { 0x00, };
    uint32_t * rk;  // pointer for round key
    unsigned int nk, nr;
    unsigned int key_byte_len;
    unsigned int i;
                        unsigned int j;

    rk = (uint32_t *)context->round_key;
    nk = context->key_len;
    key_byte_len = nk * 8;
    nr = 16 + (nk / 2);

    // X←K
    memcpy(X, key, nk);
                        // printf("key >> ");
                        // for (i = 0; i < nk / 4; ++i) printf("%08X ", X[i]);
                        // printf("\n");
    if (key_byte_len == 128)
    {
        // fori = 0 to 23 do
        //     X[0] ← ROL1 (X[0] + RCi0)    // RCi0 = ROL(delta[i mod 4], i)
        //     X[1] ← ROL3 (X[1] + RCi1)    // RCi1 = ROL(delta[i mod 4], i + 1)
        //     X[2] ← ROL6 (X[2] + RCi2)    // RCi2 = ROL(delta[i mod 4], i + 2)
        //     X[3] ← ROL11(X[3] + RCi3)    // RCi3 = ROL(delta[i mod 4], i + 3)
        //     RKi ← (X[0], X[1], X[2], X[1], X[3], X[1])
        // end for
        for (i = 0; i < nr; ++i)
        {
            rk[0]                   = X[0] = ROL(X[0] + ROL(delta[i % 4], i  ), 1);
            rk[1] = rk[3] = rk[5]   = X[1] = ROL(X[1] + ROL(delta[i % 4], i+1), 3);
            rk[2]                   = X[2] = ROL(X[2] + ROL(delta[i % 4], i+2), 6);
            rk[4]                   = X[3] = ROL(X[3] + ROL(delta[i % 4], i+3), 11);
                        // printf("RK[%d]=\t", i);
                        // for (j = 0; j < LEA_ROUND_KEY_LEN; ++j) printf("%08X ", rk[j]);
                        // printf("\n");
            rk += LEA_ROUND_KEY_LEN;
        }
    }
    else if (key_byte_len == 192)
    {
        for (i = 0; i < nr; ++i)
        {
            rk[0] = X[0] = ROL(X[0] + ROL(delta[i % 6], i    ),  1);
            rk[1] = X[1] = ROL(X[1] + ROL(delta[i % 6], i + 1),  3);
            rk[2] = X[2] = ROL(X[2] + ROL(delta[i % 6], i + 2),  6);
            rk[3] = X[3] = ROL(X[3] + ROL(delta[i % 6], i + 3), 11);
            rk[4] = X[4] = ROL(X[4] + ROL(delta[i % 6], i + 4), 13);
            rk[5] = X[5] = ROL(X[5] + ROL(delta[i % 6], i + 5), 17);
                        // printf("RK[%d]=\t", i);
                        // for (j = 0; j < LEA_ROUND_KEY_LEN; ++j) printf("%08X ", rk[j]);
                        // printf("\n");
            rk += LEA_ROUND_KEY_LEN;
        }
    }
    else
    {
        for (i = 0; i < nr; ++i)
        {
            rk[0] = X[(6 * i    ) % 8] = ROL(X[(6 * i    ) % 8] + ROL(delta[i % 8], i    ),  1);
            rk[1] = X[(6 * i + 1) % 8] = ROL(X[(6 * i + 1) % 8] + ROL(delta[i % 8], i + 1),  3);
            rk[2] = X[(6 * i + 2) % 8] = ROL(X[(6 * i + 2) % 8] + ROL(delta[i % 8], i + 2),  6);
            rk[3] = X[(6 * i + 3) % 8] = ROL(X[(6 * i + 3) % 8] + ROL(delta[i % 8], i + 3), 11);
            rk[4] = X[(6 * i + 4) % 8] = ROL(X[(6 * i + 4) % 8] + ROL(delta[i % 8], i + 4), 13);
            rk[5] = X[(6 * i + 5) % 8] = ROL(X[(6 * i + 5) % 8] + ROL(delta[i % 8], i + 5), 17);
                        // printf("RK[%d]=\t", i);
                        // for (j = 0; j < LEA_ROUND_KEY_LEN; ++j) printf("%08X ", rk[j]);
                        // printf("\n");
            rk += LEA_ROUND_KEY_LEN;
        }
    }
}

void LEA_dec_key_schedule(lea_context * context, uint32_t * key)
{
    uint32_t X[8] = { 0x00, };
    uint32_t * rk;  // pointer for round key
    unsigned int nk, nr;
    unsigned int key_byte_len;
    unsigned int i;
                        unsigned int j;

    rk = (uint32_t *)context->round_key;
    nk = context->key_len;
    key_byte_len = nk * 8;
    nr = 16 + (nk / 2);

    // X←K
    memcpy(X, key, nk);
                        // printf("key >> ");
                        // for (i = 0; i < nk / 4; ++i) printf("%08X ", X[i]);
                        // printf("\n");
    if (key_byte_len == 128)
    {
        // fori = 0 to 23 do
            // X[0] ← ROL1(X[0] + ROLi(δ[i mod 4]))
            // X[1] ← ROL3(X[1] + ROLi+1(δ[i mod 4]))
            // X[2] ← ROL6(X[2] + ROLi+2(δ[i mod 4]))
            // X[3] ← ROL11(X[3] + ROLi+3(δ[i mod 4]))
            // RK23-i ← (X[0], X[1], X[2], X[1], X[3], X[1])
        // end for
        rk += nr * LEA_ROUND_KEY_LEN;
        for (i = 0; i < nr; ++i)
        {
            rk -= LEA_ROUND_KEY_LEN;
            rk[0]                   = X[0] = ROL(X[0] + ROL(delta[i%4], i  ), 1);
            rk[1] = rk[3] = rk[5]   = X[1] = ROL(X[1] + ROL(delta[i%4], i+1), 3);
            rk[2]                   = X[2] = ROL(X[2] + ROL(delta[i%4], i+2), 6);
            rk[4]                   = X[3] = ROL(X[3] + ROL(delta[i%4], i+3), 11);
                        // printf("RK[%d]=\t", nr-i-1);
                        // for (j = 0; j < LEA_ROUND_KEY_LEN; ++j) printf("%08X ", rk[j]);
                        // printf("\n");
        }
    }
    else if (key_byte_len == 192)
    {
        rk += nr * LEA_ROUND_KEY_LEN;
        for (i = 0; i < nr; ++i)
        {
            rk -= LEA_ROUND_KEY_LEN;
            rk[0] = X[0] = ROL(X[0] + ROL(delta[i % 6], i    ),  1);
            rk[1] = X[1] = ROL(X[1] + ROL(delta[i % 6], i + 1),  3);
            rk[2] = X[2] = ROL(X[2] + ROL(delta[i % 6], i + 2),  6);
            rk[3] = X[3] = ROL(X[3] + ROL(delta[i % 6], i + 3), 11);
            rk[4] = X[4] = ROL(X[4] + ROL(delta[i % 6], i + 4), 13);
            rk[5] = X[5] = ROL(X[5] + ROL(delta[i % 6], i + 5), 17);
                        // printf("RK[%d]=\t", nr-i-1);
                        // for (j = 0; j < LEA_ROUND_KEY_LEN; ++j) printf("%08X ", rk[j]);
                        // printf("\n");
        }
    }
    else
    {
        rk += nr * LEA_ROUND_KEY_LEN;
        for (i = 0; i < nr; ++i)
        {
            rk -= LEA_ROUND_KEY_LEN;
            rk[0] = X[(6 * i    ) % 8] = ROL(X[(6 * i    ) % 8] + ROL(delta[i % 8], i    ),  1);
            rk[1] = X[(6 * i + 1) % 8] = ROL(X[(6 * i + 1) % 8] + ROL(delta[i % 8], i + 1),  3);
            rk[2] = X[(6 * i + 2) % 8] = ROL(X[(6 * i + 2) % 8] + ROL(delta[i % 8], i + 2),  6);
            rk[3] = X[(6 * i + 3) % 8] = ROL(X[(6 * i + 3) % 8] + ROL(delta[i % 8], i + 3), 11);
            rk[4] = X[(6 * i + 4) % 8] = ROL(X[(6 * i + 4) % 8] + ROL(delta[i % 8], i + 4), 13);
            rk[5] = X[(6 * i + 5) % 8] = ROL(X[(6 * i + 5) % 8] + ROL(delta[i % 8], i + 5), 17);
                        // printf("RK[%d]=\t", nr-i-1);
                        // for (j = 0; j < LEA_ROUND_KEY_LEN; ++j) printf("%08X ", rk[j]);
                        // printf("\n");
        }
    }
}

void LEA_enc_round(uint32_t * X, uint32_t * round_key)
{
    uint32_t temp = X[0];

    // X [0] ← ROL9((X[0]^RKienc[0])+(X[1]^RKienc[1]))
    // X [1] ← ROR5((X[1]^RKienc[2])+(X[2]^RKienc[3]))
    // X [2] ← ROR3((X[2]^RKienc[4])+(X[3]^RKienc[5]))
    // Xi+1[3] ← Xi[0]
    X[0] = ROL((X[0] ^ round_key[0]) + (X[1] ^ round_key[1]), 9);
    X[1] = ROR((X[1] ^ round_key[2]) + (X[2] ^ round_key[3]), 5);
    X[2] = ROR((X[2] ^ round_key[4]) + (X[3] ^ round_key[5]), 3);
    X[3] = temp;
}

void LEA_dec_round(uint32_t * X, uint32_t * round_key)
{
    uint32_t temp;
    uint32_t temp2;
    // Xi+1[0] ← Xi[3]
    // Xi+1[1] ← (ROR9(Xi[0])-(Xi+1[0]^RKidec[0]))^RKidec[1]
    // Xi+1[2] ← (ROL5(Xi[1])-(Xi+1[1]^RKidec[2]))^RKidec[3]
    // Xi+1[3] ← (ROL3(Xi[2])-(Xi+1[2]^RKidec[4]))^RKidec[5]
    temp = X[0];
    X[0] = X[3];

    temp2 = X[1];
    X[1] = (ROR(temp,  9) - (X[0] ^ round_key[0])) ^ round_key[1];

    temp = X[2];
    X[2] = (ROL(temp2, 5) - (X[1] ^ round_key[2])) ^ round_key[3];

    X[3] = (ROL(temp,  3) - (X[2] ^ round_key[4])) ^ round_key[5];
}

uint32_t ROL(uint32_t target, unsigned int rot)
{
    rot %= 32;
    if (rot == 0) return target;
    return (target << rot) ^ (target >> (32 - rot));
}

uint32_t ROR(uint32_t target, unsigned int rot)
{
    rot %= 32;
    if (rot == 0) return target;
    return (target >> rot) ^ (target << (32 - rot));
}
