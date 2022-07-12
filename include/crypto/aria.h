#ifndef _ARIA_H_
#define _ARIA_H_

#include <stdint.h>
#include <stdio.h>
#include "./../block.h"

#define ARIA_BLOCK_SIZE 16
#define ARIA_MAX_ROUND  17

typedef struct {
    unsigned int nk;
    uint8_t round_key[ARIA_MAX_ROUND][ARIA_BLOCK_SIZE];
} aria_context;

/**
 * @brief 주어진 한 블록에 대해 ARIA 암호화를 수행하는 함수
 * 
 * @param cipher_text   암호화 결과가 저장될 공간
 * @param plain_text    암호화시킬 평문
 * @param key           암호화에 사용할 키
 * @param key_len       암호화 키 길이
 */
void ARIA_encrypt(uint8_t * output, uint8_t * input, uint8_t * key, unsigned int key_len);

/**
 * @brief 주어진 한 블록에 대해 ARIA 복호화를 수행하는 함수
 * 
 * @param cipher_text   복호화 결과가 저장될 공간
 * @param plain_text    복호화시킬 암호문
 * @param key           복호화에 사용할 키
 * @param key_len       복호화 키 길이
 */
void ARIA_decrypt(uint8_t * output, uint8_t * input, uint8_t * key, unsigned int key_len);

/**
 * @brief ARIA 수행 전 구조체를 초기화하는 함수
 * 
 * @param context   초기화할 구조체의 포인터
 */
void ARIA_init(aria_context * context);

/**
 * @brief 암복호화를 위해 키를 확장하는 함수. 초기화 과정과 라운드 키 생성 과정의 두 부분으로 나뉜다.
 * 
 * @param context   라운드 키를 저장받을 구조체. 키 길이를 저장하고 있어야한다.
 * @param key       확장시킬 암호화 키
 * @param ENC_DEC   암호화 : ENCRYPT / 복호화 : DECRYPT
 */
void key_expansion(aria_context * context, uint8_t * key, PROCESS ENC_DEC);

/**
 * @brief 키 확장 중 초기화 과정을 수행하는 함수.
 * 
 * @param W     초기화를 수행한 결과를 저장할 공간
 * @param key   확장시킬 암호화 키. 키 확장 후 제로화된다.
 * @param nk    암호화 키 길이
 */
void key_init(uint8_t W[4][16], uint8_t * key, unsigned int nk);

/**
 * @brief SPN 형태의 라운드 함수. 내부적으로 XOR, Substitution, Permutation 을 수행한다.
 * 
 * @param out       라운드 함수 결과를 저장할 공간
 * @param in        입력 데이터
 * @param CK_i      초기화 상수
 * @param is_odd    라운드의 홀짝 여부. 홀수 = 1, 짝수 = 0
 */
void round_function(uint8_t * out, uint8_t * in, const uint8_t * CK, unsigned int is_odd);

/**
 * @brief 한 블록 크기(16 byte) 의 입력에 대한 XOR 값을 계산한다.
 * 
 * @param dest  XOR 연산 결과값이 저장될 공간
 * @param src1  XOR 연산 대상 1. dest 와 src1 에 같은 포인터를 주면 src1 ^= src2 와 같은 효과를 볼 수 있다.
 * @param src2  XOR 연산 대상 2. dest 와 다른 포인터여야한다.
 */
void ARIA_XOR(uint8_t * dest, uint8_t * src1, const uint8_t * src2);

/**
 * @brief confusion 부여를 위해 substitution(치환) 을 수행하는 함수. XOR 이 수행된 데이터가 들어와야한다.
 *
 * @param x         치환을 수행할 데이터
 * @param is_odd   라운드의 홀짝 여부. 홀수 = 1, 짝수 = 0
 */
void ARIA_substitution(uint8_t * x, unsigned int is_odd);

/**
 * @brief diffusion 부여를 위해 permutation(순환) 을 수행하는 함수. substitution 이 수행된 데이터가 들어와야한다.
 * 
 * @param y 순환 결과를 저장할 공간
 * @param x 순환을 수행할 입력 데이터
 */
void ARIA_diffusion(uint8_t * y, const uint8_t * x);

/**
 * @brief 키 확장 중 라운드키 생성을 수행하는 함수.
 * 
 * @param context   라운드키가 저장될 공간과 암호키 길이 정보를 가지고 있는 구조체의 포인터
 * @param W         라운드 키 생성에 사용할 초기화 결과 키
 * @param ENC_DEC   암호화 : ARIA_ENCRYPT / 복호화 : ARIA_DECRYPT
 */
void make_round_key(aria_context * context, uint8_t W[4][16], unsigned int ENC_DEC);

/**
 * @brief ROT_target 을 rout_count 만큼 ROT 한 후, XOR_target 과 XOR 한 결과를 out 에 저장한다.
 * 
 * @param out           결과가 저장될 공간
 * @param XOR_target    XOR 연산에 사용될 대상
 * @param ROT_target    ROT 연산을 수행할 대상
 * @param rot_count     ROT 비트 수
 */
void ROT_XOR(uint8_t * out, uint8_t * XOR_target, uint8_t * ROT_target, unsigned int rot_count);

#endif
