#ifndef _LEA_H_
#define _LEA_H_

#include "./../block.h"

#define LEA_BLOCK_SIZE      16
#define LEA_MAX_ROUND       32
#define LEA_ROUND_KEY_LEN   6

typedef struct {
    unsigned int nk;
    uint32_t round_key[LEA_MAX_ROUND][LEA_ROUND_KEY_LEN];
}

/**
 * @brief 주어진 한 블록에 대해 LEA 암호화를 수행하는 함수
 * 
 */
void LEA_encrypt();

#endif
