#ifndef _LEA_H_
#define _LEA_H_

#include "./../block.h"

#define LEA_BLOCK_SIZE      16
#define LEA_MAX_ROUND       32
#define LEA_ROUND_KEY_LEN   6

typedef struct {
    unsigned int key_len;
    uint32_t round_key[LEA_MAX_ROUND][LEA_ROUND_KEY_LEN];
} lea_context;

/**
 * @brief 주어진 한 블록에 대해 LEA 암호화를 수행하는 함수
 *
 * @param output    암호화 결과가 저장될 공간
 * @param input     암호화시킬 평문
 * @param key       암호화에 사용할 키
 * @param key_len   암호화 키 길이
 */
void LEA_encrypt(uint8_t * output, uint8_t * input, uint8_t * key_8, unsigned int key_len);

/**
 * @brief 주어진 한 블록에 대해 LEA 복호화를 수행하는 함수
 * 
 * @param output    복호화 결과가 저장될 공간
 * @param input     복호화시킬 암호문
 * @param key       복호화에 사용할 키
 * @param key_len   복호화 키 길이
 */
void LEA_decrypt(uint8_t * output, uint8_t * input, uint8_t * key_8, unsigned int key_len);

/**
 * @brief LEA 수행 전 구조체를 초기화하는 함수
 * 
 * @param context   초기화할 구조체의 포인터
 */
void LEA_init(lea_context * context);

/**
 * @brief 암호화를 위한 라운드키 생성함수
 * 
 * @param context   라운드 키를 저장받을 구조체. 키 길이를 저장하고 있어야한다.
 * @param key       라운드 키 생성을 위한 암호화 키
 */
void LEA_enc_key_schedule(lea_context * context, uint32_t * key);

/**
 * @brief 복호화를 위한 라운드키 생성함수. 라운드키와 순서만 반대이다.
 * 
 * @param context   라운드 키를 저장받을 구조체. 키 길이를 저장하고 있어야한다.
 * @param key       라운드 키 생성을 위한 복호화 키
 */
void LEA_dec_key_schedule(lea_context * context, uint32_t * key);

/**
 * @brief 암호화 과정의 라운드 함수
 * 
 * @param X         라운드 함수를 적용시킬 벡터
 * @param round_key 라운드 함수에 사용할 라운드 키
 */
void LEA_enc_round(uint32_t * X, uint32_t * round_key);

/**
 * @brief 복호화 과정의 라운드 함수
 * 
 * @param X         라운드 함수를 적용시킬 벡터
 * @param round_key 라운드 함수에 사용할 라운드 키
 */
void LEA_dec_round(uint32_t * X, uint32_t * round_key);

/**
 * @brief 좌측 로테이션 함수
 * 
 * @param target    로테이션 대상
 * @param rot       로테이션 카운트
 * @return uint32_t 로테이션 시킨 결과값
 */
uint32_t ROL(uint32_t target, unsigned int rot);

/**
 * @brief 
 * 
 * @param target    로테이션 대상
 * @param rot       로테이션 카운트
 * @return uint32_t 로테이션 시킨 결과값
 */
uint32_t ROR(uint32_t target, unsigned int rot);

#endif
