#ifndef _SEED_H_
#define _SEED_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SEED_ENCRYPT    0x00000000
#define SEED_DECRYPT    0x00000001


uint8_t KC[16][4] =
{
    {0x9e, 0x37, 0x79, 0xb9}, {0x3c, 0x6e, 0xf3, 0x73}, {0x78, 0xdd, 0xe6, 0xe6}, {0xf1, 0xbb, 0xcd, 0xcc},
    {0xe3, 0x77, 0x9b, 0x99}, {0xc6, 0xef, 0x37, 0x33}, {0x8d, 0xde, 0x6e, 0x67}, {0x1b, 0xbc, 0xdc, 0xcf},
    {0x37, 0x79, 0xb9, 0x9e}, {0x6e, 0xf3, 0x73, 0x3c}, {0xdd, 0xe6, 0xe6, 0x78}, {0xbb, 0xcd, 0xcc, 0xf1},
    {0x77, 0x9b, 0x99, 0xe3}, {0xef, 0x37, 0x33, 0xc6}, {0xde, 0x6e, 0x67, 0x8d}, {0xbc, 0xdc, 0xcf, 0x1b}
};

void SEED_encrypt(uint8_t * out, uint8_t * in, uint8_t * key, unsigned int ENC_DEC);

void function_F();

/**
 * @brief 내부적으로 S-Box 연산과 and, XOR 연산을 수행하는 SP 연산
 * 
 * @param out   연산 결과가 저장될 공간
 * @param in    연산을 수행할 입력 데이터
 */
void function_G(uint32_t * out, uint32_t * in);

#endif