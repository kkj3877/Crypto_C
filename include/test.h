#ifndef _TEST_H_
#define _TEST_H_

#include <stdlib.h>
#include "./block.h"
#include "./util.h"

// ARIA TEST
void test_ARIA_128(void);
void test_ARIA_128_ECB(target_data * data_enc, target_data * data_dec);
void test_ARIA_128_CBC(target_data * data_enc, target_data * data_dec);
void test_ARIA_128_CFB(target_data * data_enc, target_data * data_dec);
void test_ARIA_128_OFB(target_data * data_enc, target_data * data_dec);
void test_ARIA_128_CTR(target_data * data_enc, target_data * data_dec);

void test_ARIA_192(void);
void test_ARIA_192_ECB(target_data * data_enc, target_data * data_dec);
void test_ARIA_192_CBC(target_data * data_enc, target_data * data_dec);
void test_ARIA_192_CTR(target_data * data_enc, target_data * data_dec);

void test_ARIA_256(void);
void test_ARIA_256_ECB(target_data * data_enc, target_data * data_dec);
void test_ARIA_256_CBC(target_data * data_enc, target_data * data_dec);
void test_ARIA_256_CTR(target_data * data_enc, target_data * data_dec);


// LEA TEST
void test_LEA_ONE(void);

void test_LEA_128(void);
void test_LEA_128_ECB(target_data * data_enc, target_data * data_dec);


#endif
