#include <string.h>
#include "./../include/block.h"
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
                case CTR:

                    break;
            }
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
                        printf("    plain text : ");
                        for (j = 0; j < ARIA_BLOCK_SIZE; ++j) printf("%02X ", input[j]);
                        printf("\n");

        crypto(output, input, key, key_len);

                        printf("encrypted text : ");
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
                        for (j = 0; j < ARIA_BLOCK_SIZE; ++j) printf("%02X ", input[j]);
                        printf("\n");
            block_XOR(X, input, iv);
            crypto(output, X, key, key_len);

                        printf("encrypted text : ");
                        for (j = 0; j < ARIA_BLOCK_SIZE; ++j) printf("%02X ", output[j]);
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
                        printf("    plain text : ");
                        for (j = 0; j < ARIA_BLOCK_SIZE; ++j) printf("%02X ", input[j]);
                        printf("\n");
            crypto(X, input, key, key_len);
            block_XOR(output, X, iv);

                        printf("encrypted text : ");
                        for (j = 0; j < ARIA_BLOCK_SIZE; ++j) printf("%02X ", output[j]);
                        printf("\n\n");
                        
            if (i == block_num - 1)
                break;

            iv = input;
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }
}
