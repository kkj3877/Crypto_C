#include "./../include/test.h"
#include "./../include/crypto/lea.h"

int main(void)
{
    // test_LEA_ONE();

    // test_LEA_128();
    // test_LEA_192();
    test_LEA_256();

    return 0;
}

void test_LEA_ONE(void)
{
    unsigned int i;

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t==================| LEA - 128 |===================\n");
    printf("\t==================================================\n");

    uint8_t key[16] = {
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
    };
    uint8_t plain_text[LEA_BLOCK_SIZE] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t encrypted_text[LEA_BLOCK_SIZE];
    uint8_t decrypted_text[LEA_BLOCK_SIZE];

    LEA_encrypt(encrypted_text, plain_text, key, 16);
    printf("CT : ");
    for (i = 0; i < LEA_BLOCK_SIZE; ++i) printf("%02X ", encrypted_text[i]);
    printf("\n");
}

void test_LEA_128(void)
{
    unsigned int data_len_2 = LEA_BLOCK_SIZE * 2;
    unsigned int data_len_3 = LEA_BLOCK_SIZE * 3;
    unsigned int key_len = 16;
    unsigned int iv_len = LEA_BLOCK_SIZE;

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t==================| LEA - 128 |===================\n");
    printf("\t==================================================\n");

    target_data data_enc_2;
    target_data data_dec_2;

    target_data data_enc_3;
    target_data data_dec_3;

    data_init(&data_enc_2, data_len_2, key_len, iv_len);
    data_init(&data_dec_2, data_len_2, key_len, iv_len);

    data_init(&data_enc_3, data_len_3, key_len, iv_len);
    data_init(&data_dec_3, data_len_3, key_len, iv_len);

    // ECB MODE
    test_LEA_128_ECB(&data_enc_2, &data_dec_2);
    
    // CBC MODE
    test_LEA_128_CBC(&data_enc_3, &data_dec_3);

    // CFB MODE
    test_LEA_128_CFB(&data_enc_3, &data_dec_2);

    // CFB MODE
    test_LEA_128_OFB(&data_enc_3, &data_dec_3);

    // CTR MODE
    test_LEA_128_CTR(&data_enc_3, &data_dec_3);

    data_free(&data_enc_2);
    data_free(&data_dec_2);

    data_free(&data_enc_3);
    data_free(&data_dec_3);
}

void test_LEA_128_ECB(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"158B43008F3F065FB349C4CDB69BFCD7BD5799D19F84D224ED064FE830CD8DB6";
    unsigned char * encrypt_key_str = (unsigned char *)"7AEC775F7D4F493F1EF020CD7BFEBFD0";
    unsigned char * encrypt_answer = (unsigned char *)"8D5A5B9B4D26A9F335BBA930E7D6E983BE0E880A3AE4A6E6DAA8720F1B25C940";

    unsigned char * encrypted_text_str = (unsigned char *)"F4955B65D3DA210A6287AE0F056D48B4A989CAF4F4BF8EE3770D76A60F872D17";
    unsigned char * decrypt_key_str = (unsigned char *)"9AC4A3A3B967F62FC47681A74E431C17";
    unsigned char * decrypt_answer = (unsigned char *)"8161DBCEC0B8D8118BD83211A38E551A6FB57C0C9F4F750F0FD5A483EECB4B36";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 128 - ECB |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);

    block_cipher(LEA|ENCRYPT|ECB, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|ECB, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}

void test_LEA_128_CBC(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"974461CEA66F1554723A6977ED5C8BBC5B9B734C1088C6497B6AFB5E6378BC9A714B8F7EEF92B554CF0852C3EFA3CFA1";
    unsigned char * encrypt_key_str = (unsigned char *)"45E7759A2E1A481BFEF0334FBEDD2C69";
    unsigned char * encrypt_iv_str = (unsigned char *)"A5C7CF9FE1B9498194DB74891CA243F3";
    unsigned char * encrypt_answer = (unsigned char *)"A0E6FA2146EE69C5349D76C371B50EF2F1BF7BCF09C717FD23D204D959D9A340D2D0DC95A07AEE78025ED14C97B574AE";

    unsigned char * encrypted_text_str = (unsigned char *)"45847A0F51700D6DDDE98F1358E2762469C0A2F215B999D3631639F51ACACB38464ED040F268B0EF47ACA0F0F851B131";
    unsigned char * decrypt_key_str = (unsigned char *)"E6922558E9EF2071C13714726599422B";
    unsigned char * decrypt_iv_str = (unsigned char *)"B096F842031358E032AC5AAA9E4C15F3";
    unsigned char * decrypt_answer = (unsigned char *)"9EFA3A2F24F6E1AB9D05887C180958B6ABD4ABDE123ECCA19A75FDC53E95BF610F794D49D9D06ACD03735CA3B7F63921";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 128 - CBC |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);
    string_to_hex_array(data_enc->iv, data_enc->iv_len * 2, encrypt_iv_str);

    block_cipher(LEA|ENCRYPT|CBC, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);
    string_to_hex_array(data_dec->iv, data_dec->iv_len * 2, decrypt_iv_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|CBC, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}

void test_LEA_128_CFB(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"AF67419DFBFD5814A70940776A3A7D8D0227DC3DC891AAF487E823478E112DDA046747807C00BCA3C9311CE71454EC0A";
    unsigned char * encrypt_key_str = (unsigned char *)"862544E342E0821DFBC00761F3C9557B";
    unsigned char * encrypt_iv_str = (unsigned char *)"D8C798385092DACAD591766DC37DCF4B";
    unsigned char * encrypt_answer = (unsigned char *)"5762B9AA0E69EC4F24FED2E05D9F5C048CEC8987D9BA5691647FFF1679BE4D218C443C017E294E5DC2E5590F018ADDBC";

    unsigned char * encrypted_text_str = (unsigned char *)"2E78DC4FFF97BED82D26BC1C6EFC2CA81A286B1C701996E91A77D87AEB5CA199";
    unsigned char * decrypt_key_str = (unsigned char *)"16B8C2C58B3ADBDA63ACDA23FDBF3A77";
    unsigned char * decrypt_iv_str = (unsigned char *)"E2ABE47056745DCC2D6B3D13E0F9E37A";
    unsigned char * decrypt_answer = (unsigned char *)"E09867082A22D0F71C4E875D87770C0C05A0E8B68DB6E355441476C9964D83C3";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 128 - CFB |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);
    string_to_hex_array(data_enc->iv, data_enc->iv_len * 2, encrypt_iv_str);

    block_cipher(LEA|ENCRYPT|CFB, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);
    string_to_hex_array(data_dec->iv, data_dec->iv_len * 2, decrypt_iv_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|CFB, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}

void test_LEA_128_OFB(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"925AD9C6ED2430E663820FA076C51466E188FD5071361CBB16CC06373AE08CA051E3EC8AB2A348E2A51356D3BD4F5AE7";
    unsigned char * encrypt_key_str = (unsigned char *)"83FF7C23054C634A3CE1365F9744F2B9";
    unsigned char * encrypt_iv_str = (unsigned char *)"1F27133550EB07D82764E3B67CDC5512";
    unsigned char * encrypt_answer = (unsigned char *)"589A2911B02DB7A1966CD1ED5F8EE39271CE70F75BEC4D7EEE58D2D673436D75768E74013A215E1E36BE57348F339DB1";

    unsigned char * encrypted_text_str = (unsigned char *)"48B934067B5092F816E37D25C08B78AE6B942059828861A0AD7AE3A01C71C285A376B64FD5E47CBA7180A38C5F6ABB35";
    unsigned char * decrypt_key_str = (unsigned char *)"E6922558E9EF2071C13714726599422B";
    unsigned char * decrypt_iv_str = (unsigned char *)"B096F842031358E032AC5AAA9E4C15F3";
    unsigned char * decrypt_answer = (unsigned char *)"9EFA3A2F24F6E1AB9D05887C180958B6ABD4ABDE123ECCA19A75FDC53E95BF610F794D49D9D06ACD03735CA3B7F63921";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 128 - OFB |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);
    string_to_hex_array(data_enc->iv, data_enc->iv_len * 2, encrypt_iv_str);

    block_cipher(LEA|ENCRYPT|OFB, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);
    string_to_hex_array(data_dec->iv, data_dec->iv_len * 2, decrypt_iv_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|OFB, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}

void test_LEA_128_CTR(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"925AD9C6ED2430E663820FA076C51466E188FD5071361CBB16CC06373AE08CA051E3EC8AB2A348E2A51356D3BD4F5AE7";
    unsigned char * encrypt_key_str = (unsigned char *)"83FF7C23054C634A3CE1365F9744F2B9";
    unsigned char * encrypt_iv_str = (unsigned char *)"1F27133550EB07D82764E3B67CDC5512";
    unsigned char * encrypt_answer = (unsigned char *)"589A2911B02DB7A1966CD1ED5F8EE392A054A60DAB746A9C56FD9B52F905917A3E758C228C6E0AD26F8DF4E001C71E21";

    unsigned char * encrypted_text_str = (unsigned char *)"48B934067B5092F816E37D25C08B78AE94B13ABF58DCDCB5DCF60D9C1DF2A42EF15696D6131F134D270587D0C27C3CC9";
    unsigned char * decrypt_key_str = (unsigned char *)"E6922558E9EF2071C13714726599422B";
    unsigned char * decrypt_iv_str = (unsigned char *)"B096F842031358E032AC5AAA9E4C15F3";
    unsigned char * decrypt_answer = (unsigned char *)"9EFA3A2F24F6E1AB9D05887C180958B6ABD4ABDE123ECCA19A75FDC53E95BF610F794D49D9D06ACD03735CA3B7F63921";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 128 - CTR |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);
    string_to_hex_array(data_enc->iv, data_enc->iv_len * 2, encrypt_iv_str);

    block_cipher(LEA|ENCRYPT|CTR, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);
    string_to_hex_array(data_dec->iv, data_dec->iv_len * 2, decrypt_iv_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|CTR, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}


void test_LEA_192(void)
{
    unsigned int data_len_2 = LEA_BLOCK_SIZE * 2;
    unsigned int data_len_3 = LEA_BLOCK_SIZE * 3;
    unsigned int key_len = 24;
    unsigned int iv_len = LEA_BLOCK_SIZE;

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t==================| LEA - 192 |===================\n");
    printf("\t==================================================\n");

    target_data data_enc_2;
    target_data data_dec_2;

    target_data data_enc_3;
    target_data data_dec_3;

    data_init(&data_enc_2, data_len_2, key_len, iv_len);
    data_init(&data_dec_2, data_len_2, key_len, iv_len);

    data_init(&data_enc_3, data_len_3, key_len, iv_len);
    data_init(&data_dec_3, data_len_3, key_len, iv_len);

    // ECB MODE
    test_LEA_192_ECB(&data_enc_2, &data_dec_2);
    
    // CBC MODE
    test_LEA_192_CBC(&data_enc_3, &data_dec_3);

    // CFB MODE
    test_LEA_192_CFB(&data_enc_3, &data_dec_2);

    // OFB MODE
    test_LEA_192_OFB(&data_enc_3, &data_dec_3);

    // CTR MODE
    test_LEA_192_CTR(&data_enc_3, &data_dec_3);

    data_free(&data_enc_2);
    data_free(&data_dec_2);

    data_free(&data_enc_3);
    data_free(&data_dec_3);
}

void test_LEA_192_ECB(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"BD5799D19F84D224ED064FE830CD8DB6714C83B7FF2D86016C436A24D9C0EAFF";
    unsigned char * encrypt_key_str = (unsigned char *)"1EF020CD7BFEBFD0158B43008F3F065FB349C4CDB69BFCD7";
    unsigned char * encrypt_answer = (unsigned char *)"A87DF3B56DD995403DEB299E9F5DEF04CD00054A60193180C23363CBA3C45C73";

    unsigned char * encrypted_text_str = (unsigned char *)"903EEF777E1589CD3E0C46DA4970271B67F0C20986B066F578E22B91F27FD07C";
    unsigned char * decrypt_key_str = (unsigned char *)"C47681A74E431C178161DBCEC0B8D8118BD83211A38E551A";
    unsigned char * decrypt_answer = (unsigned char *)"6FB57C0C9F4F750F0FD5A483EECB4B361F9609DADF92A0B6A960FB9B567D6F1A";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 192 - ECB |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);

    block_cipher(LEA|ENCRYPT|ECB, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|ECB, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}

void test_LEA_192_CBC(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"7B6AFB5E6378BC9A714B8F7EEF92B554CF0852C3EFA3CFA19B0E7D08545A7BACCFF1D96B41CBFD26DAE446D08FEDF0C4";
    unsigned char * encrypt_key_str = (unsigned char *)"A5C7CF9FE1B9498194DB74891CA243F3974461CEA66F1554";
    unsigned char * encrypt_iv_str = (unsigned char *)"723A6977ED5C8BBC5B9B734C1088C649";
    unsigned char * encrypt_answer = (unsigned char *)"3A4CD2EB45982BECB12E6FC9769614AD6B42B4E622875EE2FF3EBD6814C4B2367ADAB3326C6D76EAE564D9BCDC6CDF15";

    unsigned char * encrypted_text_str = (unsigned char *)"7E94C07236FFF8AA7BD5285AF275D1F46C9A6E575FE9A0C3D4BB1C62A278CD549A6BF0C7754EF5A9A8DEF55BEF53B493";
    unsigned char * decrypt_key_str = (unsigned char *)"B096F842031358E032AC5AAA9E4C15F39EFA3A2F24F6E1AB";
    unsigned char * decrypt_iv_str = (unsigned char *)"9D05887C180958B6ABD4ABDE123ECCA1";
    unsigned char * decrypt_answer = (unsigned char *)"9A75FDC53E95BF610F794D49D9D06ACD03735CA3B7F63921437C61AFBFD04C7DF0B286716D6FF76400B5688D4FA4433D";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 192 - CBC |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);
    string_to_hex_array(data_enc->iv, data_enc->iv_len * 2, encrypt_iv_str);

    block_cipher(LEA|ENCRYPT|CBC, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);
    string_to_hex_array(data_dec->iv, data_dec->iv_len * 2, decrypt_iv_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|CBC, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}

void test_LEA_192_CFB(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"87E823478E112DDA046747807C00BCA3C9311CE71454EC0A2CC89D0F1C3ABB9B0323679F209207372D2C3CD2EE711594";
    unsigned char * encrypt_key_str = (unsigned char *)"D8C798385092DACAD591766DC37DCF4BAF67419DFBFD5814";
    unsigned char * encrypt_iv_str = (unsigned char *)"A70940776A3A7D8D0227DC3DC891AAF4";
    unsigned char * encrypt_answer = (unsigned char *)"7B38907368F60CD651E093AF518EEE8837DE01D1C626BFB66C614F6E8AE161A22D4FDC50A41EF76097BA6C46D6FC854A";

    unsigned char * encrypted_text_str = (unsigned char *)"F3116617F45220D327911607C6D54455FE4EA9452D477B950B2ED1F2A3898BF5";
    unsigned char * decrypt_key_str = (unsigned char *)"63ACDA23FDBF3A77E2ABE47056745DCC2D6B3D13E0F9E37A";
    unsigned char * decrypt_iv_str = (unsigned char *)"E09867082A22D0F71C4E875D87770C0C";
    unsigned char * decrypt_answer = (unsigned char *)"05A0E8B68DB6E355441476C9964D83C3862544E342E0821DFBC00761F3C9557B";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 192 - CFB |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);
    string_to_hex_array(data_enc->iv, data_enc->iv_len * 2, encrypt_iv_str);

    block_cipher(LEA|ENCRYPT|CFB, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);
    string_to_hex_array(data_dec->iv, data_dec->iv_len * 2, decrypt_iv_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|CFB, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}

void test_LEA_192_OFB(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"16CC06373AE08CA051E3EC8AB2A348E2A51356D3BD4F5AE768DB516FC42B6F24B469CC0E34725BA5E9221B37FCD19189";
    unsigned char * encrypt_key_str = (unsigned char *)"1F27133550EB07D82764E3B67CDC5512925AD9C6ED2430E6";
    unsigned char * encrypt_iv_str = (unsigned char *)"63820FA076C51466E188FD5071361CBB";
    unsigned char * encrypt_answer = (unsigned char *)"A835D9D84BFC2A54E1989AB764CE605369794F4433AEF6E457758D1FC1714F7EE9A0F0D6B29F6678F263FD1C48E1B83C";

    unsigned char * encrypted_text_str = (unsigned char *)"4B2241F01632E3A3F77D6A2373ABC152204B24B0F0D74DCA31B9528358974F25C6DE72F6AA14267CD748E93BA819EBB8";
    unsigned char * decrypt_key_str = (unsigned char *)"B096F842031358E032AC5AAA9E4C15F39EFA3A2F24F6E1AB";
    unsigned char * decrypt_iv_str = (unsigned char *)"9D05887C180958B6ABD4ABDE123ECCA1";
    unsigned char * decrypt_answer = (unsigned char *)"9A75FDC53E95BF610F794D49D9D06ACD03735CA3B7F63921437C61AFBFD04C7DF0B286716D6FF76400B5688D4FA4433D";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 192 - OFB |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);
    string_to_hex_array(data_enc->iv, data_enc->iv_len * 2, encrypt_iv_str);

    block_cipher(LEA|ENCRYPT|OFB, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);
    string_to_hex_array(data_dec->iv, data_dec->iv_len * 2, decrypt_iv_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|OFB, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}

void test_LEA_192_CTR(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"16CC06373AE08CA051E3EC8AB2A348E2A51356D3BD4F5AE768DB516FC42B6F24B469CC0E34725BA5E9221B37FCD19189";
    unsigned char * encrypt_key_str = (unsigned char *)"1F27133550EB07D82764E3B67CDC5512925AD9C6ED2430E6";
    unsigned char * encrypt_iv_str = (unsigned char *)"63820FA076C51466E188FD5071361CBB";
    unsigned char * encrypt_answer = (unsigned char *)"A835D9D84BFC2A54E1989AB764CE605379493B7D5084B2030ECC556F0F4968B19A7C3A9FF0EB62D5E12BDE9D4DEB1006";

    unsigned char * encrypted_text_str = (unsigned char *)"4B2241F01632E3A3F77D6A2373ABC152B69417B8F00C4F1293489FCC5064F2B961669B54B002AC89B34ED767444B5C6D";
    unsigned char * decrypt_key_str = (unsigned char *)"B096F842031358E032AC5AAA9E4C15F39EFA3A2F24F6E1AB";
    unsigned char * decrypt_iv_str = (unsigned char *)"9D05887C180958B6ABD4ABDE123ECCA1";
    unsigned char * decrypt_answer = (unsigned char *)"9A75FDC53E95BF610F794D49D9D06ACD03735CA3B7F63921437C61AFBFD04C7DF0B286716D6FF76400B5688D4FA4433D";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 192 - CTR |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);
    string_to_hex_array(data_enc->iv, data_enc->iv_len * 2, encrypt_iv_str);

    block_cipher(LEA|ENCRYPT|CTR, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);
    string_to_hex_array(data_dec->iv, data_dec->iv_len * 2, decrypt_iv_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|CTR, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}


void test_LEA_256(void)
{
    unsigned int data_len_2 = LEA_BLOCK_SIZE * 2;
    unsigned int data_len_3 = LEA_BLOCK_SIZE * 3;
    unsigned int key_len = 32;
    unsigned int iv_len = LEA_BLOCK_SIZE;

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t==================| LEA - 256 |===================\n");
    printf("\t==================================================\n");

    target_data data_enc_2;
    target_data data_dec_2;

    target_data data_enc_3;
    target_data data_dec_3;

    data_init(&data_enc_2, data_len_2, key_len, iv_len);
    data_init(&data_dec_2, data_len_2, key_len, iv_len);

    data_init(&data_enc_3, data_len_3, key_len, iv_len);
    data_init(&data_dec_3, data_len_3, key_len, iv_len);

    // ECB MODE
    test_LEA_256_ECB(&data_enc_2, &data_dec_2);
    
    // CBC MODE
    test_LEA_256_CBC(&data_enc_3, &data_dec_3);

    // CFB MODE
    test_LEA_256_CFB(&data_enc_3, &data_dec_2);

    // OFB MODE
    test_LEA_256_OFB(&data_enc_3, &data_dec_3);

    // CTR MODE
    test_LEA_256_CTR(&data_enc_3, &data_dec_3);

    data_free(&data_enc_2);
    data_free(&data_dec_2);

    data_free(&data_enc_3);
    data_free(&data_dec_3);
}

void test_LEA_256_ECB(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"714C83B7FF2D86016C436A24D9C0EAFF73A849D93E853AAD125DFEC4E3E1CC89";
    unsigned char * encrypt_key_str = (unsigned char *)"158B43008F3F065FB349C4CDB69BFCD7BD5799D19F84D224ED064FE830CD8DB6";
    unsigned char * encrypt_answer = (unsigned char *)"B1D8EA41DFA20E5C58664AC4D7796F4C69BA1ADF32CE66D65E0233C81914B38B";

    unsigned char * encrypted_text_str = (unsigned char *)"A2AF6D97C5AA3440A5891EDD28CC69627B5F32297B5A241F4E5CB9D970D53D27";
    unsigned char * decrypt_key_str = (unsigned char *)"8161DBCEC0B8D8118BD83211A38E551A6FB57C0C9F4F750F0FD5A483EECB4B36";
    unsigned char * decrypt_answer = (unsigned char *)"1F9609DADF92A0B6A960FB9B567D6F1A891941F44A2668D2F1AF9536466B71B2";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 256 - ECB |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);

    block_cipher(LEA|ENCRYPT|ECB, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|ECB, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}

void test_LEA_256_CBC(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"9B0E7D08545A7BACCFF1D96B41CBFD26DAE446D08FEDF0C41D41385C4B1CC0BF6F0734FA33972E53995757D93D03D040";
    unsigned char * encrypt_key_str = (unsigned char *)"974461CEA66F1554723A6977ED5C8BBC5B9B734C1088C6497B6AFB5E6378BC9A";
    unsigned char * encrypt_iv_str = (unsigned char *)"714B8F7EEF92B554CF0852C3EFA3CFA1";
    unsigned char * encrypt_answer = (unsigned char *)"24E37E8CFF92942C83C8ED446726733DCEAB4A6CDD36495742E1B8A46A7079B0EB47C213CA6B6366240B62EBA6DE2B4E";

    unsigned char * encrypted_text_str = (unsigned char *)"FF27B673D522427A89C60338B5C16E61EEF7FB2A2F9168C983B2C82D2FDA208BE3CCE4094660A572C319FFB469B6E5A8";
    unsigned char * decrypt_key_str = (unsigned char *)"9EFA3A2F24F6E1AB9D05887C180958B6ABD4ABDE123ECCA19A75FDC53E95BF61";
    unsigned char * decrypt_iv_str = (unsigned char *)"0F794D49D9D06ACD03735CA3B7F63921";
    unsigned char * decrypt_answer = (unsigned char *)"437C61AFBFD04C7DF0B286716D6FF76400B5688D4FA4433DBC289ACD89876BD54036239F52F160DCFE0AFB9574024664";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 256 - CBC |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);
    string_to_hex_array(data_enc->iv, data_enc->iv_len * 2, encrypt_iv_str);

    block_cipher(LEA|ENCRYPT|CBC, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);
    string_to_hex_array(data_dec->iv, data_dec->iv_len * 2, decrypt_iv_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|CBC, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}

void test_LEA_256_CFB(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"2CC89D0F1C3ABB9B0323679F209207372D2C3CD2EE711594094182F8189E0BBAFDB3C1F475157587F14A29BCA188C42B";
    unsigned char * encrypt_key_str = (unsigned char *)"AF67419DFBFD5814A70940776A3A7D8D0227DC3DC891AAF487E823478E112DDA";
    unsigned char * encrypt_iv_str = (unsigned char *)"046747807C00BCA3C9311CE71454EC0A";
    unsigned char * encrypt_answer = (unsigned char *)"003D0BCF8022DACEAABC328EC84E67C920EE992C667C69E87CCAB06BCAEE3951CE8743FC9257747BC757DD14A61CC0B0";

    unsigned char * encrypted_text_str = (unsigned char *)"E12682CAEA09C9A9E199032DA9244A74FF9DD0F4EDDD679665AEAEEA4C423C09";
    unsigned char * decrypt_key_str = (unsigned char *)"E2ABE47056745DCC2D6B3D13E0F9E37AE09867082A22D0F71C4E875D87770C0C";
    unsigned char * decrypt_iv_str = (unsigned char *)"05A0E8B68DB6E355441476C9964D83C3";
    unsigned char * decrypt_answer = (unsigned char *)"862544E342E0821DFBC00761F3C9557BD8C798385092DACAD591766DC37DCF4B";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 256 - CFB |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);
    string_to_hex_array(data_enc->iv, data_enc->iv_len * 2, encrypt_iv_str);

    block_cipher(LEA|ENCRYPT|CFB, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);
    string_to_hex_array(data_dec->iv, data_dec->iv_len * 2, decrypt_iv_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|CFB, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}

void test_LEA_256_OFB(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"68DB516FC42B6F24B469CC0E34725BA5E9221B37FCD19189291D75C113EAAC83DBA8765BF0D5E95B29C29E051199AA6B";
    unsigned char * encrypt_key_str = (unsigned char *)"925AD9C6ED2430E663820FA076C51466E188FD5071361CBB16CC06373AE08CA0";
    unsigned char * encrypt_iv_str = (unsigned char *)"51E3EC8AB2A348E2A51356D3BD4F5AE7";
    unsigned char * encrypt_answer = (unsigned char *)"10C7EE67071A21AEAFFD1A92AFDA354942CE90EA038EAD58A9D2EC75A0F0D6B35053E298F37F6E11B794983DC93912F1";

    unsigned char * encrypted_text_str = (unsigned char *)"BABF00C8B308EF15C41C781BA26CC214FCB787D9F0014D3E2D2EF7AD85A06998226FAA3A7F3280AEEF498E258381F886";
    unsigned char * decrypt_key_str = (unsigned char *)"9EFA3A2F24F6E1AB9D05887C180958B6ABD4ABDE123ECCA19A75FDC53E95BF61";
    unsigned char * decrypt_iv_str = (unsigned char *)"0F794D49D9D06ACD03735CA3B7F63921";
    unsigned char * decrypt_answer = (unsigned char *)"437C61AFBFD04C7DF0B286716D6FF76400B5688D4FA4433DBC289ACD89876BD54036239F52F160DCFE0AFB9574024664";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 256 - OFB |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);
    string_to_hex_array(data_enc->iv, data_enc->iv_len * 2, encrypt_iv_str);

    block_cipher(LEA|ENCRYPT|OFB, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);
    string_to_hex_array(data_dec->iv, data_dec->iv_len * 2, decrypt_iv_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|OFB, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}

void test_LEA_256_CTR(target_data * data_enc, target_data * data_dec)
{
    unsigned int key_len = data_enc->key_len;

    uint8_t * answer;

    unsigned char * plain_text_str = (unsigned char *)"68DB516FC42B6F24B469CC0E34725BA5E9221B37FCD19189291D75C113EAAC83DBA8765BF0D5E95B29C29E051199AA6B";
    unsigned char * encrypt_key_str = (unsigned char *)"925AD9C6ED2430E663820FA076C51466E188FD5071361CBB16CC06373AE08CA0";
    unsigned char * encrypt_iv_str = (unsigned char *)"51E3EC8AB2A348E2A51356D3BD4F5AE7";
    unsigned char * encrypt_answer = (unsigned char *)"10C7EE67071A21AEAFFD1A92AFDA3549B1664501505E07F9CFDDFA5286E81643D0A1B2DD2DB164298F442C0D0DB5E43D";

    unsigned char * encrypted_text_str = (unsigned char *)"BABF00C8B308EF15C41C781BA26CC21450AB0368549AEAE5D06B85A958D4DC05EA292F9767CAEB0216AB36CCF8D7A464";
    unsigned char * decrypt_key_str = (unsigned char *)"9EFA3A2F24F6E1AB9D05887C180958B6ABD4ABDE123ECCA19A75FDC53E95BF61";
    unsigned char * decrypt_iv_str = (unsigned char *)"0F794D49D9D06ACD03735CA3B7F63921";
    unsigned char * decrypt_answer = (unsigned char *)"437C61AFBFD04C7DF0B286716D6FF76400B5688D4FA4433DBC289ACD89876BD54036239F52F160DCFE0AFB9574024664";

    printf("\n\n");
    printf("\t==================================================\n");
    printf("\t===============| LEA - 256 - CTR |================\n");
    printf("\t==================================================\n");

    answer = (uint8_t *)calloc(data_enc->input_len, sizeof(uint8_t));

    printf("==================================================\n");
                        printf(">>>> Encrypt Process start\n");

    string_to_hex_array(data_enc->input, data_enc->input_len * 2, plain_text_str);
    string_to_hex_array(data_enc->key, data_enc->key_len * 2, encrypt_key_str);
    string_to_hex_array(data_enc->iv, data_enc->iv_len * 2, encrypt_iv_str);

    block_cipher(LEA|ENCRYPT|CTR, data_enc);

    string_to_hex_array(answer, data_enc->input_len * 2, encrypt_answer);
    if (compare_vector(data_enc->output, answer, data_enc->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");
    
                        printf("==================================================\n");
                        printf(">>>> Decrypt Process start\n");
    
    string_to_hex_array(data_dec->input, data_dec->input_len * 2, encrypted_text_str);
    string_to_hex_array(data_dec->key, data_dec->key_len * 2, decrypt_key_str);
    string_to_hex_array(data_dec->iv, data_dec->iv_len * 2, decrypt_iv_str);

    printf("\n");

    block_cipher(LEA|DECRYPT|CTR, data_dec);

    string_to_hex_array(answer, data_dec->input_len * 2, decrypt_answer);
    if (compare_vector(data_dec->output, answer, data_dec->input_len))
        printf(">> PROCESS SUCCESSED\n");
    else
        printf(">> PROCESS FAILED\n");

    printf("==================================================\n");

    free(answer);
}
