#include "test.h"

void data_init(target_data * data, unsigned int data_len, unsigned int key_len, unsigned int iv_len)
{
    data->input_len = data_len;
    data->input = (uint8_t *)calloc(data_len, sizeof(uint8_t));
    data->output = (uint8_t *)calloc(data_len, sizeof(uint8_t));
    data->key_len = key_len;
    data->key = (uint8_t *)calloc(key_len, sizeof(uint8_t));
    if (iv_len != 0)
    {
        data->iv_len = iv_len;
        data->iv = (uint8_t *)calloc(iv_len, sizeof(uint8_t));
    }
    else
    {
        data->iv_len = 0;
        data->iv = (uint8_t *)NULL;
    }
}

void data_free(target_data * data)
{
    if (data->input != NULL) free(data->input);
    if (data->output != NULL) free(data->output);
    if (data->key != NULL) free(data->key);
    if (data->iv != NULL) free(data->iv);
}