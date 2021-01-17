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

void test_cbc_encrypt()
{
#if defined(AES_CBC)    
    #define NB_ENC_TESTS (1U)
    aes_ctxt_t ctxt;
    uint32_t loop=0;
    uint32_t loop_test=0;
    uint8_t res = 0;
    uint8_t pass =0;
    uint8_t fail = 0;
    uint8_t cipher_text[16];
    uint8_t * key;
    uint8_t * plain_text;
    uint8_t * expected_cipher_text;
    uint8_t * iv;

    /*
     * Adding more tests:
     *    https://www.cryptool.org/en/cto/highlights/aes-step-by-step
     *
     * NIST test vectors:
     *    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
     * KEY = 80000000000000000000000000000000
     * IV = 00000000000000000000000000000000
     * PLAINTEXT = 00000000000000000000000000000000
     * CIPHERTEXT = 0edd33d3c621e546455bd8ba1418bec8
     */
    uint8_t a_key[NB_ENC_TESTS][AES_KEY_SIZE_BYTES] = {
        {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    };

    uint8_t a_plain_text[NB_ENC_TESTS][AES_BLOCK_SIZE_BYTES] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    };

    uint8_t a_iv[NB_ENC_TESTS][AES_BLOCK_SIZE_BYTES] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    };


    uint8_t a_expected_cipher_text[NB_ENC_TESTS][AES_BLOCK_SIZE_BYTES]= {
        {0x0e, 0xdd, 0x33, 0xd3, 0xc6, 0x21, 0xe5, 0x46, 0x45, 0x5b, 0xd8, 0xba, 0x14, 0x18, 0xbe, 0xc8},
    };

    for (loop_test=0; loop_test<NB_ENC_TESTS; loop_test++)
    {
        key = a_key[loop_test];
        iv = a_iv[loop_test];
        plain_text = a_plain_text[loop_test];
        expected_cipher_text = a_expected_cipher_text[loop_test];

        res = aes_cbc_init(&ctxt, key, AES_KEY_SIZE_BYTES, iv);

        if (res == AES_INIT_SUCCESS)
        {
            res = aes_cbc_encrypt_block(&ctxt, plain_text, cipher_text);
        }

        if (res == AES_ENCRYPT_SUCCESS)
        {
            for (loop=0; loop<16; loop++)
            {
                if ((loop % 4) ==0 )
                {
                    printf("\n");
                }        
                printf("%02x ", cipher_text[loop]);

                if (cipher_text[loop] != expected_cipher_text[loop])
                {
                    res = 0xFF;
                    printf("<  ");            
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

        printf("\n");
    }

    /* Sequence test */
    /* 
     * https://datatracker.ietf.org/doc/rfc3602/?include_text=1
     * Key       : 0x56e47a38c5598974bc46903dba290349
     * IV        : 0x8ce82eefbea0da3c44699ed7db51b7d9
     * Plaintext : 0xa0a1a2a3a4a5a6a7a8a9aaabacadaeaf
     *        b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
     *         c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
     *         d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
     * Ciphertext: 0xc30e32ffedc0774e6aff6af0869f71aa
     *         0f3af07a9a31a9c684db207eb0ef8e4e
     *         35907aa632c3ffdf868bb7b29d3d46ad
     *         83ce9f9a102ee99d49a53e87f4c3da55
     */
    uint8_t s_key[16] = {0x56, 0xe4, 0x7a, 0x38, 0xc5, 0x59, 0x89, 0x74, 0xbc, 0x46, 0x90, 0x3d, 0xba, 0x29, 0x03, 0x49};
    uint8_t s_iv[16] = {0x8c, 0xe8, 0x2e, 0xef, 0xbe, 0xa0, 0xda, 0x3c, 0x44, 0x69, 0x9e, 0xd7, 0xdb, 0x51, 0xb7, 0xd9};
    uint8_t s_plain_text[4*16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
                                  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
                                  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
                                  0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf};
    uint8_t s_expected_cipher_text[4*16] = {0xc3, 0x0e, 0x32, 0xff, 0xed, 0xc0, 0x77, 0x4e, 0x6a, 0xff, 0x6a, 0xf0, 0x86, 0x9f, 0x71, 0xaa,
                                   0x0f, 0x3a, 0xf0, 0x7a, 0x9a, 0x31, 0xa9, 0xc6, 0x84, 0xdb, 0x20, 0x7e, 0xb0, 0xef, 0x8e, 0x4e,
                                   0x35, 0x90, 0x7a, 0xa6, 0x32, 0xc3, 0xff, 0xdf, 0x86, 0x8b, 0xb7, 0xb2, 0x9d, 0x3d, 0x46, 0xad,
                                   0x83, 0xce, 0x9f, 0x9a, 0x10, 0x2e, 0xe9, 0x9d, 0x49, 0xa5, 0x3e, 0x87, 0xf4, 0xc3, 0xda, 0x55};
    uint8_t s_cipher_text[4*16];
    uint8_t t_loop = 0;

    res = aes_cbc_init(&ctxt, s_key, AES_KEY_SIZE_BYTES, s_iv);

    if (res == AES_INIT_SUCCESS)
    {
        for (t_loop=0; t_loop<4; t_loop++)
        {
            res = aes_cbc_encrypt_block(&ctxt, &s_plain_text[16*t_loop], &s_cipher_text[16*t_loop]);

            if (res == AES_ENCRYPT_SUCCESS)
            {
                for (loop=0; loop<16; loop++)
                {
                    if ((loop % 4) ==0 )
                    {
                        printf("\n");
                    }        
                    printf("%02x ", s_cipher_text[16*t_loop+loop]);

                    if (s_cipher_text[16*t_loop+loop] != s_expected_cipher_text[16*t_loop+loop])
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

    printf("\n\n test_cbc_encrypt: %u PASS - %u FAIL\n", pass, fail);
#else
    printf("\n\n test_cbc_encrypt : AES_CBC disabled\n");
#endif /*AES_CBC */
}

void test_cbc_decrypt()
{
#if defined(AES_CBC)
    #define NB_DEC_TESTS (1U)
    aes_ctxt_t ctxt;
    uint32_t loop=0;
    uint32_t loop_test=0;
    uint8_t res = 0;
    uint8_t pass =0;
    uint8_t fail = 0;
    uint8_t plain_text[16];
    uint8_t * key;
    uint8_t * cipher_text;
    uint8_t * expected_plain_text;
    uint8_t * iv;

    plain_text[0] = 0xFF; /* to force a failure in case nopthing is done */

    /*
     * NIST test vectors.
     * KEY = c0000000000000000000000000000000
     * IV = 00000000000000000000000000000000
     * CIPHERTEXT = 4bc3f883450c113c64ca42e1112a9e87
     * PLAINTEXT = 00000000000000000000000000000000     
     */
    uint8_t a_key[NB_DEC_TESTS][AES_KEY_SIZE_BYTES] = {
        {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    };

    uint8_t a_cipher_text[NB_DEC_TESTS][AES_BLOCK_SIZE_BYTES] = {
        {0x4b, 0xc3, 0xf8, 0x83, 0x45, 0x0c, 0x11, 0x3c, 0x64, 0xca, 0x42, 0xe1, 0x11, 0x2a, 0x9e, 0x87}
    };

    uint8_t a_iv[NB_ENC_TESTS][AES_BLOCK_SIZE_BYTES] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    };    

    uint8_t a_expected_plain_text[NB_DEC_TESTS][AES_BLOCK_SIZE_BYTES]= {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}    };

    for (loop_test=0; loop_test<NB_DEC_TESTS; loop_test++)
    {
        key = a_key[loop_test];
        iv = a_iv[loop_test];
        cipher_text = a_cipher_text[loop_test];
        expected_plain_text = a_expected_plain_text[loop_test];

        res = aes_cbc_init(&ctxt, key, AES_KEY_SIZE_BYTES, iv);

        if (res == AES_INIT_SUCCESS)
        {
            res = aes_cbc_decrypt_block(&ctxt, cipher_text, plain_text);
        }

        if (res == AES_DECRYPT_SUCCESS)
        {
            for (loop=0; loop<16; loop++)
            {
                if ((loop % 4) ==0 )
                {
                    printf("\n");
                }        
                printf("%02x ", plain_text[loop]);

                if (plain_text[loop] != expected_plain_text[loop])
                {
                    res = 0xFF;
                    printf("<  ");            
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

        printf("\n");
    }

    /* Sequence test */
    /* 
     * https://datatracker.ietf.org/doc/rfc3602/?include_text=1
     * Key       : 0x56e47a38c5598974bc46903dba290349
     * IV        : 0x8ce82eefbea0da3c44699ed7db51b7d9
     * Plaintext : 0xa0a1a2a3a4a5a6a7a8a9aaabacadaeaf
     *        b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
     *         c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
     *         d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
     * Ciphertext: 0xc30e32ffedc0774e6aff6af0869f71aa
     *         0f3af07a9a31a9c684db207eb0ef8e4e
     *         35907aa632c3ffdf868bb7b29d3d46ad
     *         83ce9f9a102ee99d49a53e87f4c3da55
     */
    uint8_t s_key[16] = {0x56, 0xe4, 0x7a, 0x38, 0xc5, 0x59, 0x89, 0x74, 0xbc, 0x46, 0x90, 0x3d, 0xba, 0x29, 0x03, 0x49};
    uint8_t s_iv[16] = {0x8c, 0xe8, 0x2e, 0xef, 0xbe, 0xa0, 0xda, 0x3c, 0x44, 0x69, 0x9e, 0xd7, 0xdb, 0x51, 0xb7, 0xd9};
    uint8_t s_expected_plain_text[4*16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
                                  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
                                  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
                                  0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf};
    uint8_t s_cipher_text[4*16] = {0xc3, 0x0e, 0x32, 0xff, 0xed, 0xc0, 0x77, 0x4e, 0x6a, 0xff, 0x6a, 0xf0, 0x86, 0x9f, 0x71, 0xaa,
                                   0x0f, 0x3a, 0xf0, 0x7a, 0x9a, 0x31, 0xa9, 0xc6, 0x84, 0xdb, 0x20, 0x7e, 0xb0, 0xef, 0x8e, 0x4e,
                                   0x35, 0x90, 0x7a, 0xa6, 0x32, 0xc3, 0xff, 0xdf, 0x86, 0x8b, 0xb7, 0xb2, 0x9d, 0x3d, 0x46, 0xad,
                                   0x83, 0xce, 0x9f, 0x9a, 0x10, 0x2e, 0xe9, 0x9d, 0x49, 0xa5, 0x3e, 0x87, 0xf4, 0xc3, 0xda, 0x55};
    uint8_t s_plain_text[4*16];    
    uint8_t t_loop = 0;

    res = aes_cbc_init(&ctxt, s_key, AES_KEY_SIZE_BYTES, s_iv);

    if (res == AES_INIT_SUCCESS)
    {
        for (t_loop=0; t_loop<4; t_loop++)
        {
            res = aes_cbc_decrypt_block(&ctxt, &s_cipher_text[16*t_loop], &s_plain_text[16*t_loop]);

            if (res == AES_DECRYPT_SUCCESS)
            {
                for (loop=0; loop<16; loop++)
                {
                    if ((loop % 4) ==0 )
                    {
                        printf("\n");
                    }        
                    printf("%02x ", s_plain_text[16*t_loop+loop]);

                    if (s_plain_text[16*t_loop+loop] != s_expected_plain_text[16*t_loop+loop])
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

    printf("\n\n test_cbc_decrypt: %u PASS - %u FAIL\n", pass, fail);
#else
    printf("\n\n test_cbc_decrypt : AES_CBC disabled\n");
#endif /*AES_CBC */    
}