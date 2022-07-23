#include <string.h>
#include "./../include/block.h"
#include "./../include/crypto/lea.h"
#include "./../include/crypto/aria.h"

void block_XOR(uint8_t * dest, uint8_t * src1, uint8_t * src2)
{
    unsigned int i;

    for (i = 0; i < BLOCK_SIZE; ++i)
        dest[i] = src1[i] ^ src2[i];
}

void block_cipher(ORDER order, target_data * data)
{
    CRYPTO  crypto  = order & 0xF0000000;
    PROCESS process = order & 0x0F000000;
    MODE    mode    = order & 0x00F00000;

                    // printf("crypto  : %08X\n", crypto);
                    // printf("process : %08X\n", process);
                    // printf("mode    : %08X\n", mode);

    switch (crypto)
    {
        case ARIA:
            switch (mode)
            {
                case ECB:
                    if (process == ENCRYPT)
                        operate_ECB(ARIA_encrypt, data);
                    else
                        operate_ECB(ARIA_decrypt, data);
                    break;
                case CBC:
                    if (process == ENCRYPT)
                        operate_CBC(ARIA_encrypt, data, ENCRYPT);
                    else
                        operate_CBC(ARIA_decrypt, data, DECRYPT);
                    break;
                case CFB:
                    if (process == ENCRYPT)
                        operate_CFB(ARIA_encrypt, data, ENCRYPT);
                    else
                        operate_CFB(ARIA_encrypt, data, DECRYPT);
                    break;
                case OFB:
                    operate_OFB(ARIA_encrypt, data);
                    break;
                case CTR:
                    operate_CTR(ARIA_encrypt, data);
                    break;
            }
            break;
        case LEA:
            switch(mode)
            {
                case ECB:
                    if (process == ENCRYPT)
                        operate_ECB(LEA_encrypt, data);
                    else
                        operate_ECB(LEA_decrypt, data);
                    break;
                case CBC:
                    if (process == ENCRYPT)
                        operate_CBC(LEA_encrypt, data, ENCRYPT);
                    else
                        operate_CBC(LEA_decrypt, data, DECRYPT);
                    break;
                case CFB:
                    if (process == ENCRYPT)
                        operate_CFB(LEA_encrypt, data, ENCRYPT);
                    else
                        operate_CFB(LEA_encrypt, data, DECRYPT);
                    break;
                case OFB:
                    operate_OFB(LEA_encrypt, data);
                    break;
                case CTR:
                    operate_CTR(LEA_encrypt, data);
                    break;
            }
            break;
    }
}

void operate_ECB(CRYPTO_SYSTEM crypto, target_data * data)
{
    uint8_t * input;
    uint8_t * output;
    uint8_t * key;
    unsigned int key_len;
    unsigned int block_num;
    unsigned int i, j;

    // 암호화를 위한 기본 정보를 세팅한다.
    input = data->input;
    output = data->output;
    key = data->key;
    key_len = data->key_len;
    
    block_num = data->input_len / BLOCK_SIZE;

    for (i = 0; i < block_num; ++i)
    {
                        printf("    input text : ");
                        for (j = 0; j < ARIA_BLOCK_SIZE; ++j) printf("%02X ", input[j]);
                        printf("\n");
        
        crypto(output, input, key, key_len);

                        printf("processed text : ");
                        for (j = 0; j < ARIA_BLOCK_SIZE; ++j) printf("%02X ", output[j]);
                        printf("\n\n");

        output += BLOCK_SIZE;
        input += BLOCK_SIZE;
    }
}

void operate_CBC(CRYPTO_SYSTEM crypto, target_data * data, PROCESS enc_dec)
{
    uint8_t * input;
    uint8_t X[BLOCK_SIZE];
    uint8_t * output;
    uint8_t * key;
    unsigned int key_len;
    uint8_t * iv;
    unsigned int iv_len;
    unsigned int block_num;
    unsigned int i, j;

    // 암호화를 위한 기본 정보를 세팅한다.
    input = data->input;
    output = data->output;
    key = data->key;
    key_len = data->key_len;
    iv = data->iv;
    iv_len = data->iv_len;
    
    block_num = data->input_len / BLOCK_SIZE;

    if (enc_dec == ENCRYPT)
    {
        for (i = 0; i < block_num; ++i)
        {
                        printf("    plain text : ");
                        for (j = 0; j < BLOCK_SIZE; ++j) printf("%02X ", input[j]);
                        printf("\n");

            block_XOR(X, input, iv);
            crypto(output, X, key, key_len);

                        printf("encrypted text : ");
                        for (j = 0; j < BLOCK_SIZE; ++j) printf("%02X ", output[j]);
                        printf("\n\n");

            if (i == block_num - 1)
                break;
            
            iv = output;
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }
    else
    {
        for (i = 0; i < block_num; ++i)
        {
                        printf("   cipher text : ");
                        for (j = 0; j < BLOCK_SIZE; ++j) printf("%02X ", input[j]);
                        printf("\n");

            crypto(X, input, key, key_len);
            block_XOR(output, X, iv);

                        printf("decrypted text : ");
                        for (j = 0; j < BLOCK_SIZE; ++j) printf("%02X ", output[j]);
                        printf("\n\n");
                        
            if (i == block_num - 1)
                break;

            iv = input;
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }
}

void operate_CFB(CRYPTO_SYSTEM crypto, target_data * data, PROCESS enc_dec)
{
    uint8_t * input;
    uint8_t X[BLOCK_SIZE];
    uint8_t * output;
    uint8_t Y[BLOCK_SIZE];
    uint8_t * key;
    unsigned int key_len;
    uint8_t * iv;
    unsigned int iv_len;
    unsigned int block_num;
    unsigned int i, j;

    // 암호화를 위한 기본 정보를 세팅한다.
    input = data->input;
    output = data->output;
    key = data->key;
    key_len = data->key_len;
    iv = data->iv;
    iv_len = data->iv_len;
    
    block_num = data->input_len / BLOCK_SIZE;

    if (enc_dec == ENCRYPT)
    {
        memcpy(X, iv, BLOCK_SIZE);
                        
        for (i = 0; i < block_num; ++i)
        {
                        printf("    plain text : ");
                        for (j = 0; j < BLOCK_SIZE; ++j) printf("%02X ", input[j]);
                        printf("\n");

            crypto(Y, X, key, key_len);
            block_XOR(X, Y, input);
            memcpy(output, X, BLOCK_SIZE);

                        printf("encrypted text : ");
                        for (j = 0; j < BLOCK_SIZE; ++j) printf("%02X ", output[j]);
                        printf("\n\n");

            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }
    else
    {
        memcpy(X, iv, BLOCK_SIZE);
        
        for (i = 0; i < block_num; ++i)
        {
                        printf("   cipher text : ");
                        for (j = 0; j < BLOCK_SIZE; ++j) printf("%02X ", input[j]);
                        printf("\n");

            crypto(Y, X, key, key_len);
            memcpy(X, input, BLOCK_SIZE);
            block_XOR(output, Y, X);

                        printf("decrypted text : ");
                        for (j = 0; j < BLOCK_SIZE; ++j) printf("%02X ", output[j]);
                        printf("\n\n");

            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }
}

void operate_OFB(CRYPTO_SYSTEM crypto, target_data * data)
{
    uint8_t * input;
    uint8_t X[BLOCK_SIZE];
    uint8_t * output;
    uint8_t Y[BLOCK_SIZE];
    uint8_t * key;
    unsigned int key_len;
    uint8_t * iv;
    unsigned int iv_len;
    unsigned int block_num;
    unsigned int i, j;

    // 암호화를 위한 기본 정보를 세팅한다.
    input = data->input;
    output = data->output;
    key = data->key;
    key_len = data->key_len;
    iv = data->iv;
    iv_len = data->iv_len;
    
    block_num = data->input_len / BLOCK_SIZE;

    memcpy(X, iv, BLOCK_SIZE);
                    
    for (i = 0; i < block_num; ++i)
    {
                    printf("    input text : ");
                    for (j = 0; j < BLOCK_SIZE; ++j) printf("%02X ", input[j]);
                    printf("\n");

        crypto(Y, X, key, key_len);
        memcpy(X, Y, BLOCK_SIZE);
        block_XOR(output, X, input);

                    printf("processed text : ");
                    for (j = 0; j < BLOCK_SIZE; ++j) printf("%02X ", output[j]);
                    printf("\n\n");

        input += BLOCK_SIZE;
        output += BLOCK_SIZE;
    }
}

void operate_CTR(CRYPTO_SYSTEM crypto, target_data * data)
{
    uint8_t * input;
    uint8_t X[BLOCK_SIZE];
    uint8_t * output;
    uint8_t * key;
    unsigned int key_len;
    uint8_t ctr[BLOCK_SIZE];
    unsigned int block_num;
    unsigned int i, j;

    // 암호화를 위한 기본 정보를 세팅한다.
    input = data->input;
    output = data->output;
    key = data->key;
    key_len = data->key_len;
    memcpy(ctr, data->iv, BLOCK_SIZE);
    
    block_num = data->input_len / BLOCK_SIZE;
    
    for (i = 0; i < block_num; ++i)
    {
                    printf("    input text : ");
                    for (j = 0; j < ARIA_BLOCK_SIZE; ++j) printf("%02X ", input[j]);
                    printf("\n");

        crypto(X, ctr, key, key_len);
        block_XOR(output, input, X);

                    printf("processed text : ");
                    for (j = 0; j < ARIA_BLOCK_SIZE; ++j) printf("%02X ", output[j]);
                    printf("\n\n");

        increase_counter(ctr);
        input += BLOCK_SIZE;
        output += BLOCK_SIZE;
    }
}

void increase_counter(uint8_t * ctr)
{
    unsigned int i;
    for (i = BLOCK_SIZE - 1; i >= 0; --i)
    {
        ++ctr[i];
        if (ctr[i] == 0x00)
            continue;
        break;
    }
}
