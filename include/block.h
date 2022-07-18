#ifndef _BLOCK_H_
#define _BLOCK_H_

#include <stdio.h>
#include <stdint.h>

//////////////////// BLOCK CONSTANT ////////////////////
#define BLOCK_SIZE  16

//////////////////// ORDER SEGMENT ////////////////////
#define CRYPTO      uint32_t
#define ARIA        0x10000000

#define PROCESS     uint32_t
#define ENCRYPT     0x01000000
#define DECRYPT     0x02000000

#define MODE        uint32_t
#define ECB         0x00100000
#define CBC         0x00200000
#define CTR         0x00300000

//////////////////// ORDER LIST ////////////////////
#define ORDER           uint32_t
#define ARIA_ENC_ECB    0x11100000
#define ARIA_ENC_CBC    0x11200000
#define ARIA_ENC_CTR    0x11300000

#define ARIA_DEC_ECB    0x12100000
#define ARIA_DEC_CBC    0x12200000
#define ARIA_DEC_CTR    0x12300000

typedef void (*CRYPTO_SYSTEM)(uint8_t * output, uint8_t * input, uint8_t * key, unsigned int key_len);

typedef struct {
    uint8_t * input;
    unsigned int input_len;
    uint8_t * output;
    uint8_t * key;
    unsigned int key_len;
    uint8_t * iv;
    unsigned int iv_len;
} target_data;

void block_cipher(ORDER MODE, target_data * data);

void operate_ECB(CRYPTO_SYSTEM crypto, target_data * data);

void operate_CBC(CRYPTO_SYSTEM crypto, target_data * data, PROCESS enc_dec);

void operate_CTR(CRYPTO_SYSTEM crypto, target_data * data);

void increase_counter(uint8_t * ctr);

#endif
