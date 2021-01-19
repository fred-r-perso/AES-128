/* 
* MIT License

* Copyright (c) 2021 Frédéric Ruellé

* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:

* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.

* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE. 
*/

#include <stdio.h>
#include "aes.h"

/* Test vectors : https://tools.ietf.org/html/rfc3686#page-9 */

/*
 *  Test Vector #3: Encrypting 36 octets using AES-CTR with 128-bit key
 *  AES Key          : 76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC
 *  AES-CTR IV       : 27 77 7F 3F  4A 17 86 F0
 *  Nonce            : 00 E0 01 7B
 *  Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
 *                   : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
 *                   : 20 21 22 23
 *  Counter Block (1): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 01
 *  Key Stream    (1): C1 CE 4A AB 9B 2A FB DE C7 4F 58 E2 E3 D6 7C D8
 *  Counter Block (2): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 02
 *  Key Stream    (2): 55 51 B6 38 CA 78 6E 21 CD 83 46 F1 B2 EE 0E 4C
 *  Counter Block (3): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 03
 *  Key Stream    (3): 05 93 25 0C 17 55 36 00 A6 3D FE CF 56 23 87 E9
 *  Ciphertext       : C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7
 *                   : 45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53
 *                   : 25 B2 07 2F
 */
void test_ctr_encrypt()
{
#if defined(AES_CTR)    
    uint8_t plain_text[36] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                              0x20, 0x21, 0x22, 0x23};

    uint8_t expected_cipher_text[36] = {0xC1, 0xCF, 0x48, 0xA8, 0x9F, 0x2F, 0xFD, 0xD9, 0xCF, 0x46, 0x52, 0xE9, 0xEF, 0xDB, 0x72, 0xD7,
                                        0x45, 0x40, 0xA4, 0x2B, 0xDE, 0x6D, 0x78, 0x36, 0xD5, 0x9A, 0x5C, 0xEA, 0xAE, 0xF3, 0x10, 0x53,
                                        0x25, 0xB2, 0x07, 0x2F};     

    uint8_t key[16] = {0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8, 0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC};

    uint8_t nonce[12] = {0x00, 0xE0, 0x01, 0x7B, 0x27, 0x77, 0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0};  

    aes_ctxt_t ctxt;
    uint32_t loop=0;
    uint32_t t_loop=0;
    uint8_t res = 0;
    uint8_t pass =0;
    uint8_t fail = 0;
    uint8_t cipher_text[36];
    uint8_t len = 16;  

    res = aes_ctr_init(&ctxt, key, AES_KEY_SIZE_BYTES, nonce);

    /* The test vector starts with a counter of 1, not 0 */
    ctxt.init_vector[15] = 1;

    if (res == AES_INIT_SUCCESS)
    {
        for (t_loop=0; t_loop<3; t_loop++)
        {
            if (t_loop==2)
            {
                len = 4;
            }

            printf("\nlen=%u\n", len);

            res = aes_ctr_encrypt_block(&ctxt, &plain_text[16*t_loop], &cipher_text[16*t_loop], len);

            if (res == AES_ENCRYPT_SUCCESS)
            {
                for (loop=0; loop<len; loop++)
                {
                    if ((loop % 4) ==0 )
                    {
                        printf("\n");
                    }        
                    printf("%02x ", cipher_text[16*t_loop+loop]);

                    if (cipher_text[16*t_loop+loop] != expected_cipher_text[16*t_loop+loop])
                    {
                        res = 0xFF;
                        printf("<  ");            
                    }
                }
            }
        }
    }

    if (res == AES_ENCRYPT_SUCCESS)
    {   
        pass ++;
    }
    else
    {
        fail ++;
    }

    printf("\n\n test_ctr_encrypt: %u PASS - %u FAIL\n", pass, fail);
#else
    printf("\n\n test_ctr_encrypt : AES_CTR disabled\n");
#endif /*AES_CTR */
}


void test_ctr_decrypt()
{
#if defined(AES_CTR)    
    uint8_t expected_plain_text[36] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                                       0x20, 0x21, 0x22, 0x23};

    uint8_t cipher_text[36] = {0xC1, 0xCF, 0x48, 0xA8, 0x9F, 0x2F, 0xFD, 0xD9, 0xCF, 0x46, 0x52, 0xE9, 0xEF, 0xDB, 0x72, 0xD7,
                               0x45, 0x40, 0xA4, 0x2B, 0xDE, 0x6D, 0x78, 0x36, 0xD5, 0x9A, 0x5C, 0xEA, 0xAE, 0xF3, 0x10, 0x53,
                               0x25, 0xB2, 0x07, 0x2F};     

    uint8_t key[16] = {0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8, 0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC};

    uint8_t nonce[12] = {0x00, 0xE0, 0x01, 0x7B, 0x27, 0x77, 0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0};  

    aes_ctxt_t ctxt;
    uint32_t loop=0;
    uint32_t t_loop=0;
    uint8_t res = 0;
    uint8_t pass =0;
    uint8_t fail = 0;
    uint8_t plain_text[36];
    uint8_t len = 16;  

    res = aes_ctr_init(&ctxt, key, AES_KEY_SIZE_BYTES, nonce);

    /* The test vector starts with a counter of 1, not 0 */
    ctxt.init_vector[15] = 1;

    if (res == AES_INIT_SUCCESS)
    {
        for (t_loop=0; t_loop<3; t_loop++)
        {
            if (t_loop==2)
            {
                len = 4;
            }

            printf("\nlen=%u\n", len);

            res = aes_ctr_decrypt_block(&ctxt, &cipher_text[16*t_loop], &plain_text[16*t_loop], len);

            if (res == AES_DECRYPT_SUCCESS)
            {
                for (loop=0; loop<len; loop++)
                {
                    if ((loop % 4) ==0 )
                    {
                        printf("\n");
                    }        
                    printf("%02x ", plain_text[16*t_loop+loop]);

                    if (plain_text[16*t_loop+loop] != expected_plain_text[16*t_loop+loop])
                    {
                        res = 0xFF;
                        printf("<  ");            
                    }
                }
            }
        }
    }

    if (res == AES_DECRYPT_SUCCESS)
    {   
        pass ++;
    }
    else
    {
        fail ++;
    }

    printf("\n\n test_ctr_decrypt: %u PASS - %u FAIL\n", pass, fail);
#else
    printf("\n\n test_ctr_decrypt : AES_CTR disabled\n");
#endif /*AES_CTR */
}

void test_ctr_counter()
{
#if defined(AES_CTR) 
    aes_ctxt_t ctxt;
    uint8_t key[16] = {0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8, 0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC};
    uint8_t nonce[12] = {0x00, 0xE0, 0x01, 0x7B, 0x27, 0x77, 0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0};  
    uint8_t plain_text[16] = {0};
    uint8_t cipher_text[16];
    uint64_t loop = 0;
    uint8_t res;
    uint64_t max_test = UINT16_MAX;

    max_test = max_test + 1; /* UINT32_MAX +1 without overflow */

    printf("\n testing up to: %lu\n", max_test);

    res = aes_ctr_init(&ctxt, key, AES_KEY_SIZE_BYTES, nonce);

    if (res == AES_INIT_SUCCESS)
    {
        for (loop=0; loop<=max_test; loop++)
        {
            res = aes_ctr_encrypt_block(&ctxt, plain_text, cipher_text, 16);

            if (res == AES_ENCRYPT_SUCCESS)
            {
                uint32_t counter = 0;
                uint32_t loop_c=0;
                uint32_t temp = 0;

                /* extract counter */
                for (loop_c=0; loop_c<AES_CTR_COUNTER_LEN_BYTES; loop_c ++)
                {
                    temp = (uint32_t)(ctxt.init_vector[AES_CTR_NONCE_LEN_BYTES+loop_c]);
                    temp = temp << (8*(AES_CTR_COUNTER_LEN_BYTES-1-loop_c));
                    counter = counter | temp;
                }              

                if (loop == UINT32_MAX)
                {
                    if (counter != 0)
                    {
                        res = 0xFF;
                        printf("\n(error) counter is %u instead of %u\n", counter, 0);                        
                        break;
                    }
                }
                else if (loop == max_test)
                {
                    if (max_test > UINT32_MAX)
                    {
                        if (counter != 1)
                        {
                            res = 0xFF;
                            printf("\n(error) counter is %u instead of %u\n", counter, 1);                        
                            break;
                        }
                        else
                        {
                            printf("\n wrap-around well handled\n");
                            /* stop testing */
                            break;
                        }
                    }
                    else
                    {
                        if (counter != loop+1)
                        {
                            res = 0xFF;
                            printf("\n(error) counter is %u instead of %lu\n", counter, loop+1);
                            break;
                        }
                    }
                }
                else if (counter != loop+1)
                {
                    res = 0xFF;
                    printf("\n(error) counter is %u instead of %lu\n", counter, loop+1);
                    break;
                }
            }
            else
            {
                printf("\nencrypt failure\n");
                break;
            }
        }
    }
    
    if (res == AES_ENCRYPT_SUCCESS)
    {
        printf("\n\n test_ctr_counter: PASS\n");
    }
    else
    {
        printf("\n\n test_ctr_counter: FAIL\n");
    }
#else
    printf("\n\n test_ctr_counter : AES_CTR disabled\n");
#endif /*AES_CTR */    
}