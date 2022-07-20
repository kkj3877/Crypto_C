#include "util.h"

int get_num(unsigned char ch)
{
	int num = 0;
	if (ch >= '0' && ch <= '9')
	{
		num = ch - 0x30;
	}
	else
	{
		switch (ch)
		{
		case 'A':
		case 'a':
			num = 10;
			break;
		case 'B':
		case 'b':
			num = 11;
			break;
		case 'C':
		case 'c':
			num = 12;
			break;
		case 'D':
		case 'd':
			num = 13;
			break;
		case 'E':
		case 'e':
			num = 14;
			break;
		case 'F':
		case 'f':
			num = 15;
			break;
		default:
			num = 0;
		}
	}
	return num;
}

int string_to_hex_array(uint8_t * hex_array, unsigned int str_len, unsigned char * string)
{
	int i = 0;
	
	unsigned int out_len = 0;

	// 입력받은 Hex String을 hex 값으로 저장하기위한 길이
	//     예시) "ab"  (2byte) => 0xab (1byte)
	//     예시) "abc" (3byte) => 0xab 0xc0 (2byte)
	out_len = (str_len / 2) + (str_len % 2);

	for (i = 0; i < out_len; ++i)
	{
		hex_array[i] = 0x00;
		hex_array[i] = get_num(string[i * 2]) << 4;
		if (i * 2 + 1 <= str_len)
		{
			hex_array[i] |= get_num(string[i * 2 + 1]);
		}
	}
	return out_len;
}

void uint8_to_uint32(uint32_t * dest, uint8_t * src, unsigned int bytes)
{
    unsigned int i;
    bytes /= 4;
    for (i = 0; i < bytes; ++i)
    {
        dest[i]  = (0x00 ^ src[4 * i + 3]) << 24;
        dest[i] ^= (0x00 ^ src[4 * i + 2]) << 16;
        dest[i] ^= (0x00 ^ src[4 * i + 1]) <<  8;
        dest[i] ^=  0x00 ^ src[4 * i + 0];
    }
}

void uint8_to_uint32_reverse_order(uint32_t * dest, uint8_t * src, unsigned int bytes)
{
    unsigned int i;
    bytes /= 4;
    for (i = 0; i < bytes; ++i)
    {
        dest[i]  =  0x00 ^ src[4 * i + 0];
        dest[i] ^= (0x00 ^ src[4 * i + 1]) <<  8;
        dest[i] ^= (0x00 ^ src[4 * i + 2]) << 16;
        dest[i] ^= (0x00 ^ src[4 * i + 3]) << 24;
    }
}

void uint32_to_uint8(uint8_t * dest, uint32_t * src, unsigned int bytes)
{
    unsigned int i;
    
    for (i = 0; i < bytes; i += 4)
    {
        dest[i  ] = (uint8_t)(src[i / 4] >> 24);
        dest[i+1] = (uint8_t)(src[i / 4] >> 16);
        dest[i+2] = (uint8_t)(src[i / 4] >>  8);
        dest[i+3] = (uint8_t)(src[i / 4]);
    }
}

void uint32_to_uint8_reverse_order(uint8_t * dest, uint32_t * src, unsigned int bytes)
{
    unsigned int i;
    
    for (i = 0; i < bytes; i += 4)
    {
        dest[i  ] = (uint8_t)(src[i / 4]);
        dest[i+1] = (uint8_t)(src[i / 4] >>  8);
        dest[i+2] = (uint8_t)(src[i / 4] >> 16);
        dest[i+3] = (uint8_t)(src[i / 4] >> 24);
    }
}
