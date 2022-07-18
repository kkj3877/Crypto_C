#include "./../include/seed.h"

char numtochar(unsigned int num)
{
    switch(num) {
        case 0:
            return '0';
        case 1:
            return '1';
        case 2:
            return '2';
        case 3:
            return '3';
        case 4:
            return '4';
        case 5:
            return '5';
        case 6:
            return '6';
        case 7:
            return '7';
        case 8:
            return '8';
        case 9:
            return '9';
        case 10:
            return 'a';
        case 11:
            return 'b';
        case 12:
            return 'c';
        case 13:
            return 'd';
        case 14:
            return 'e';
        case 15:
            return 'f';
    }
}

int main(void)
{
    uint8_t key[16] = {
        0x9F, 0x38, 0x79, 0xB9, 0x64, 0xCB, 0x88, 0x49,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t plain_text = { 0x00, };
    uint8_t encrypted_text = { 0x00, };
    uint8_t cipher_text = {
        0x9B, 0x48, 0x30, 0x4C, 0xAA, 0xAE, 0x2A, 0xB1,
        0xC5, 0x30, 0x3C, 0xAA, 0x47, 0x06, 0x9C, 0x4D
    };

    SEED_encrypt(encrypted_text, plain_text, key, SEED_ENCRYPT);

    int nums[256] = {

    };

    for (int i = 0; i < 256; ++i)
    {
        printf("0x%c%c ", numtochar(nums[i]/16), numtochar(nums[i]%16));
        if (i % 16 == 15) printf("\n");
    }

    return 0;
}


