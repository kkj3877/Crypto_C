#include "util.h"
#include <stdio.h>

unsigned int compare_vector(uint8_t * v1, uint8_t * v2, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len ; ++i)
	{
		// printf("%02X %02X\n", v1[i], v2[i]);
		if (v1[i] != v2[i])
			return 0;
	}

	return 1;
}

int get_num(unsigned char ch)
{
	if (ch >= '0' && ch <= '9')
	{
		return ch - 0x30;
	}
	else
	{
		switch (ch)
		{
		case 'A':
		case 'a':
			return 10;
			break;
		case 'B':
		case 'b':
			return 11;
			break;
		case 'C':
		case 'c':
			return 12;
			break;
		case 'D':
		case 'd':
			return 13;
			break;
		case 'E':
		case 'e':
			return 14;
			break;
		case 'F':
		case 'f':
			return 15;
			break;
		default:
			return 0;
		}
	}
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
