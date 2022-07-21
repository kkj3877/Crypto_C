#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h>

unsigned int compare_vector(uint8_t * v1, uint8_t * v2, unsigned int len);

int get_num(unsigned char ch);
int string_to_hex_array(uint8_t * hex_array, unsigned int in_str_len, unsigned char * string);

void uint8_to_uint32(uint32_t * dest, uint8_t * src, unsigned int bytes);
void uint8_to_uint32_reverse_order(uint32_t * dest, uint8_t * src, unsigned int bytes);
void uint32_to_uint8(uint8_t * dest, uint32_t * src, unsigned int bytes);
void uint32_to_uint8_reverse_order(uint8_t * dest, uint32_t * src, unsigned int bytes);

#endif
