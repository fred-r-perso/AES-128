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

/* 
 * See : https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers 
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
 */

#include <stdio.h>
#include "aes.h"
#include "aes_cbc_test.h"
#include "aes_ctr_test.h"

/* private functions of the lib */
/* ---------------------------- */
uint32_t RotWord(uint32_t k);
uint32_t SubWord(uint32_t k);
void KeyExpansion(uint32_t * expandedKey, uint32_t * key);
void getRoundKey(uint32_t * expandedKey, uint8_t * roundKey, uint8_t round);
void ShiftRows(uint8_t * text);
void InvShiftRows(uint8_t * text);
#if defined(LOOKUP_GF256)
void do_mult_encrypt(uint8_t * column);
#else
void do_mult(uint8_t * column, const uint8_t * matrix);
#endif /* LOOKUP_GF256 */

/* test functions prototypes */
/* ------------------------- */
void test_RotWord();
void test_SubWord();
void test_KeyExpansion();
void test_getRoundKey();
void test_ShiftRows();
void test_InvShiftRows();
void test_do_mult();

void test_init();
void test_encrypt();
void test_decrypt();

/* test routine */
/* ------------ */
int main()
{
    /* Helpers */
    test_RotWord();
    test_SubWord();
    test_KeyExpansion();
    test_getRoundKey();
    test_ShiftRows();
    test_InvShiftRows();
    test_do_mult();

    /* AES API */
    test_init();
    test_encrypt();
    test_decrypt();

    /* CBC mode of operation */
    test_cbc_encrypt();
    test_cbc_decrypt();

    /* CTR mode of operation */
    test_ctr_encrypt();
    test_ctr_decrypt();
    test_ctr_counter();

    return(0);
}


/* test functions */
/* -------------- */
void test_RotWord()
{
    uint8_t pass =0;
    uint8_t fail = 0;
    uint32_t input=0xAABBCCDD;
    uint32_t output=0xBBCCDDAA;

    if (RotWord(input) != output)
    {
        fail ++;
        printf("\n[error] : %x instead of %x\n", RotWord(input), output);        
    }
    else
    {
        pass ++;
    }

    printf("\n test_RotWord : %u PASS - %u FAIL\n", pass, fail );    
}

void test_SubWord()
{
    uint8_t pass =0;
    uint8_t fail = 0;
    uint32_t input=0x01020304;
    uint32_t output=0x7c777bf2;

    if (SubWord(input) != output)
    {
        fail ++;
        printf("\n[error] : %x instead of %x\n", SubWord(input), output);        
    }
    else
    {
        pass ++;
    }

    printf("\n test_SubWord : %u PASS - %u FAIL\n", pass, fail );    
}

void test_KeyExpansion()
{
    /* test vectors from: https://www.samiam.org/key-schedule.html */
    uint32_t expandedKey[44]; /* AES-128 */
    uint32_t * expectedKey;
    uint32_t inputKey[4];     /* AES-128 */
    uint8_t pass =0;
    uint8_t fail = 0;
    uint8_t local_fail = 0;
    uint8_t loop;
    uint8_t printLoop=0;

    inputKey[0] = 0;
    inputKey[1] = 0;
    inputKey[2] = 0;
    inputKey[3] = 0;

    uint32_t nullKey[44] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x62636363, 0x62636363, 0x62636363, 0x62636363, 
    0x9b9898c9, 0xf9fbfbaa, 0x9b9898c9, 0xf9fbfbaa, 
    0x90973450, 0x696ccffa, 0xf2f45733, 0x0b0fac99, 
    0xee06da7b, 0x876a1581, 0x759e42b2, 0x7e91ee2b, 
    0x7f2e2b88, 0xf8443e09, 0x8dda7cbb, 0xf34b9290, 
    0xec614b85, 0x1425758c, 0x99ff0937, 0x6ab49ba7, 
    0x21751787, 0x3550620b, 0xacaf6b3c, 0xc61bf09b, 
    0x0ef90333, 0x3ba96138, 0x97060a04, 0x511dfa9f, 
    0xb1d4d8e2, 0x8a7db9da, 0x1d7bb3de, 0x4c664941, 
    0xb4ef5bcb, 0x3e92e211, 0x23e951cf, 0x6f8f188e};

    local_fail = 0;
    expectedKey = nullKey;

    KeyExpansion(expandedKey, inputKey);

    for (loop=0; loop<44; loop++)
    {
        if ((loop % 4) ==0 )
        {
            printf("\n");
        }

        for (printLoop=0; printLoop<4; printLoop++)
        {
            printf("%02x ", (uint8_t)((expandedKey[loop]>>(24-8*printLoop)) & 0x000000FF));
        }

        if (expandedKey[loop] != expectedKey[loop])
        {
            local_fail = 1;
            printf("<  ");
        }
    }

    if (local_fail == 0)
    {
        pass ++;
    }
    else
    {
        fail ++;
    }

    /* next key : 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f */    
    inputKey[0] = 0x00010203;
    inputKey[1] = 0x04050607;
    inputKey[2] = 0x08090a0b;
    inputKey[3] = 0x0c0d0e0f;

    uint32_t nextKey[44] = {
    0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 
    0xd6aa74fd, 0xd2af72fa, 0xdaa678f1, 0xd6ab76fe, 
    0xb692cf0b, 0x643dbdf1, 0xbe9bc500, 0x6830b3fe,
    0xb6ff744e, 0xd2c2c9bf, 0x6c590cbf, 0x0469bf41, 
    0x47f7f7bc, 0x95353e03, 0xf96c32bc, 0xfd058dfd, 
    0x3caaa3e8, 0xa99f9deb, 0x50f3af57, 0xadf622aa, 
    0x5e390f7d, 0xf7a69296, 0xa7553dc1, 0x0aa31f6b, 
    0x14f9701a, 0xe35fe28c, 0x440adf4d, 0x4ea9c026, 
    0x47438735, 0xa41c65b9, 0xe016baf4, 0xaebf7ad2, 
    0x549932d1, 0xf0855768, 0x1093ed9c, 0xbe2c974e, 
    0x13111d7f, 0xe3944a17, 0xf307a78b, 0x4d2b30c5};

    local_fail = 0;
    expectedKey = nextKey;

    KeyExpansion(expandedKey, inputKey);

    printf("\n\n----------\n");

    for (loop=0; loop<44; loop++)
    {
        if ((loop % 4) ==0 )
        {
            printf("\n");
        }

        for (printLoop=0; printLoop<4; printLoop++)
        {
            printf("%02x ", (uint8_t)((expandedKey[loop]>>(24-8*printLoop)) & 0x000000FF));
        }

        if (expandedKey[loop] != expectedKey[loop])
        {
            local_fail = 1;
            printf("<  ");
        }
    }

    if (local_fail == 0)
    {
        pass ++;
    }
    else
    {
        fail ++;
    }

    /* summary */
    printf("\n\n test_KeyExpansion : %u PASS - %u FAIL\n", pass, fail );    
}

void test_getRoundKey()
{
    uint32_t loop=0;
    uint8_t pass =0;
    uint8_t fail = 0;
    uint8_t local_fail = 0;
    uint8_t roundKey[16];
    uint32_t nullKey[44] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x62636363, 0x62636363, 0x62636363, 0x62636363, 
    0x9b9898c9, 0xf9fbfbaa, 0x9b9898c9, 0xf9fbfbaa, 
    0x90973450, 0x696ccffa, 0xf2f45733, 0x0b0fac99, 
    0xee06da7b, 0x876a1581, 0x759e42b2, 0x7e91ee2b, 
    0x7f2e2b88, 0xf8443e09, 0x8dda7cbb, 0xf34b9290, 
    0xec614b85, 0x1425758c, 0x99ff0937, 0x6ab49ba7, 
    0x21751787, 0x3550620b, 0xacaf6b3c, 0xc61bf09b, 
    0x0ef90333, 0x3ba96138, 0x97060a04, 0x511dfa9f, 
    0xb1d4d8e2, 0x8a7db9da, 0x1d7bb3de, 0x4c664941, 
    0xb4ef5bcb, 0x3e92e211, 0x23e951cf, 0x6f8f188e};

    getRoundKey(nullKey, roundKey, 0);

    printf("\n");
    for (loop=0; loop<16; loop++)
    {
        printf("%02x ", roundKey[loop]);

        if (roundKey[loop]!=0)
        {
            printf("<  ");
            local_fail++;
        }
    }

    if (local_fail == 0)
    {
        pass ++;
    }
    else
    {
        fail ++;
    }

    local_fail = 0;

    getRoundKey(nullKey, roundKey, 1);

    uint8_t round1_expectedKey[16] = {0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63};

    printf("\n");

    for (loop=0; loop<16; loop++)
    {
        printf("%02x ", roundKey[loop]);

        if (roundKey[loop]!=round1_expectedKey[loop])
        {
            printf("<  ");
            local_fail++;
        }
    }

    if (local_fail == 0)
    {
        pass ++;
    }
    else
    {
        fail ++;
    }

    local_fail = 0;

    getRoundKey(nullKey, roundKey, 10); /* last round for AES-128 */

    uint8_t round10_expectedKey[16] = {0xb4, 0xef, 0x5b, 0xcb, 0x3e, 0x92, 0xe2, 0x11, 0x23, 0xe9, 0x51, 0xcf, 0x6f, 0x8f, 0x18, 0x8e};

    printf("\n");

    for (loop=0; loop<16; loop++)
    {
        printf("%02x ", roundKey[loop]);

        if (roundKey[loop]!=round10_expectedKey[loop])
        {
            printf("<  ");
            local_fail++;
        }
    }

    if (local_fail == 0)
    {
        pass ++;
    }
    else
    {
        fail ++;
    }


    /* summary */
    printf("\n\n test_getRoundKey : %u PASS - %u FAIL\n", pass, fail );  
}

void test_ShiftRows()
{
    uint32_t loop = 0;
    uint8_t fail = 0;

    /* 
     * AES operates on a 4 × 4 column-major order array of bytes, termed the state.
     * So in memory, the consecutive bytes are the column.
     */
    uint8_t block[16] = {0x00, 0x01, 0x02, 0x03, /* state column 1 */
                         0x04, 0x05, 0x06, 0x07, /* state column 2 */
                         0x08, 0x09, 0x0a, 0x0b, /* state column 3 */
                         0x0c, 0x0d, 0x0e, 0x0f};/* state column 4 */

    uint8_t shifted_block[16] = {0x00, 0x05, 0x0a, 0x0f,
                                 0x04, 0x09, 0x0e, 0x03,
                                 0x08, 0x0d, 0x02, 0x07,
                                 0x0c, 0x01, 0x06, 0x0b};

    ShiftRows(block);

    for (loop=0; loop<16; loop++)
    {   
        if (loop % 4 == 0)
        {
            printf("\n");
        }
        printf("%02x ", block[loop]);
        if (block[loop] != shifted_block[loop])
        {
            fail++;
            printf("<  ");
        }
    }

    if (fail == 0)
    {
        printf("\n\n test_ShiftRows: PASSED\n");
    }
    else
    {
        printf("\n\n test_ShiftRows: FAILED\n");
    }    
}

void test_InvShiftRows()
{
    uint32_t loop = 0;
    uint8_t fail = 0;

    /* 
     * AES operates on a 4 × 4 column-major order array of bytes, termed the state.
     * So in memory, the consecutive bytes are the column.
     */
    uint8_t block[16] = {0x00, 0x01, 0x02, 0x03, /* state column 1 */
                         0x04, 0x05, 0x06, 0x07, /* state column 2 */
                         0x08, 0x09, 0x0a, 0x0b, /* state column 3 */
                         0x0c, 0x0d, 0x0e, 0x0f};/* state column 4 */

    uint8_t shifted_block[16] = {0x00, 0x05, 0x0a, 0x0f,
                                 0x04, 0x09, 0x0e, 0x03,
                                 0x08, 0x0d, 0x02, 0x07,
                                 0x0c, 0x01, 0x06, 0x0b};

    InvShiftRows(shifted_block);

    for (loop=0; loop<16; loop++)
    {   
        if (loop % 4 == 0)
        {
            printf("\n");
        }
        printf("%02x ", shifted_block[loop]);
        if (block[loop] != shifted_block[loop])
        {
            fail++;
            printf("<  ");
        }
    }

    if (fail == 0)
    {
        printf("\n\n test_InvShiftRows: PASSED\n");
    }
    else
    {
        printf("\n\n test_InvShiftRows: FAILED\n");
    }    
}

void test_do_mult()
{
#if !defined(LOOKUP_GF256)
    extern uint8_t MixColumns_Matrix[16];
#endif /* LOOKUP_GF256 */
    /* test vectors : https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn() */
    uint8_t column[4] = {0xdb, 0x13, 0x53, 0x45};
    uint8_t mixed_column[4] = {0x8e, 0x4d, 0xa1, 0xbc};
    uint32_t loop=0;
    uint8_t res = 0;

#if defined(LOOKUP_GF256)
    do_mult_encrypt(column);
#else
    /* encrypt direction */
    do_mult(column, MixColumns_Matrix);
#endif /* LOOKUP_GF256 */    

    printf("\n");
    for (loop=0; loop<4; loop++)
    {
        printf("%02x ", column[loop]);

        if (column[loop] != mixed_column[loop])
        {
            res ++;
            printf("<  ");
        }
    }

    if (res == 0)
    {
        printf("\n\n test_do_mult: PASSED\n");
    }
    else
    {
        printf("\n\n test_do_mult: FAILED\n");
    }
}


/* API */
/* --- */

void test_init()
{
    aes_ctxt_t ctxt;
    uint8_t res = 0;
    uint8_t key[AES_KEY_SIZE_BYTES] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    res = aes_init(&ctxt, key, AES_KEY_SIZE_BYTES);

    if (res == AES_INIT_SUCCESS)
    {
        uint32_t loop=0;
        uint32_t printLoop=0;
        uint32_t expandedKey[44] = {
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 
            0xd6aa74fd, 0xd2af72fa, 0xdaa678f1, 0xd6ab76fe, 
            0xb692cf0b, 0x643dbdf1, 0xbe9bc500, 0x6830b3fe,
            0xb6ff744e, 0xd2c2c9bf, 0x6c590cbf, 0x0469bf41, 
            0x47f7f7bc, 0x95353e03, 0xf96c32bc, 0xfd058dfd, 
            0x3caaa3e8, 0xa99f9deb, 0x50f3af57, 0xadf622aa, 
            0x5e390f7d, 0xf7a69296, 0xa7553dc1, 0x0aa31f6b, 
            0x14f9701a, 0xe35fe28c, 0x440adf4d, 0x4ea9c026, 
            0x47438735, 0xa41c65b9, 0xe016baf4, 0xaebf7ad2, 
            0x549932d1, 0xf0855768, 0x1093ed9c, 0xbe2c974e, 
            0x13111d7f, 0xe3944a17, 0xf307a78b, 0x4d2b30c5 };

            for (loop=0; loop<44; loop++)
            {
                if ((loop % 4) ==0 )
                {
                    printf("\n");
                }

                for (printLoop=0; printLoop<4; printLoop++)
                {
                    printf("%02x ", (uint8_t)((ctxt.expKey[loop]>>(24-8*printLoop)) & 0x000000FF));
                }

                if (expandedKey[loop] != ctxt.expKey[loop])
                {
                    res = 0xFF;
                    printf("<  ");
                }
            }
    }

    if (res == AES_INIT_SUCCESS)
    {
        printf("\n\n test_init: PASSED\n");
    }
    else
    {
        printf("\n\n test_init: FAILED\n");
    }
}

void test_encrypt()
{
    #define NB_ENC_TESTS (5U)
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

    /*
     * Adding more tests:
     *    https://www.cryptool.org/en/cto/highlights/aes-step-by-step
     *
     * NIST test vectors:
     *    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
     * Test 0:
     *    KEY = 00000000000000000000000000000000
     *    PLAINTEXT = 80000000000000000000000000000000
     *    CIPHERTEXT = 3ad78e726c1ec02b7ebfe92b23d9ec34
     */
    uint8_t a_key[NB_ENC_TESTS][AES_KEY_SIZE_BYTES] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae ,0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
        {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00}
    };

    uint8_t a_plain_text[NB_ENC_TESTS][AES_BLOCK_SIZE_BYTES] = {
        {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    };

    uint8_t a_expected_cipher_text[NB_ENC_TESTS][AES_BLOCK_SIZE_BYTES]= {
        {0x3a, 0xd7, 0x8e, 0x72, 0x6c, 0x1e, 0xc0, 0x2b, 0x7e, 0xbf, 0xe9, 0x2b, 0x23, 0xd9, 0xec, 0x34},
        {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97},
        {0x4b, 0xc3, 0xf8, 0x83, 0x45, 0x0c, 0x11, 0x3c, 0x64, 0xca, 0x42, 0xe1, 0x11, 0x2a, 0x9e, 0x87},
        {0x72, 0xa1, 0xda, 0x77, 0x0f, 0x5d, 0x7a, 0xc4, 0xc9, 0xef, 0x94, 0xd8, 0x22, 0xaf, 0xfd, 0x97},
        {0x62, 0xd0, 0x66, 0x2d, 0x6e, 0xae, 0xdd, 0xed, 0xeb, 0xae, 0x7f, 0x7e, 0xa3, 0xa4, 0xf6, 0xb6}
    };

    for (loop_test=0; loop_test<NB_ENC_TESTS; loop_test++)
    {
        key = a_key[loop_test];
        plain_text = a_plain_text[loop_test];
        expected_cipher_text = a_expected_cipher_text[loop_test];

        res = aes_init(&ctxt, key, AES_KEY_SIZE_BYTES);

        if (res == AES_INIT_SUCCESS)
        {
            res = aes_encrypt_block(&ctxt, plain_text, cipher_text);
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

    printf("\n\n test_encrypt: %u PASS - %u FAIL\n", pass, fail);
}

void test_decrypt()
{
    #define NB_DEC_TESTS (5U)
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

    /*
     * NIST test vectors.
     */
    uint8_t a_key[NB_DEC_TESTS][AES_KEY_SIZE_BYTES] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    };

    uint8_t a_cipher_text[NB_DEC_TESTS][AES_BLOCK_SIZE_BYTES] = {
        {0x3a, 0xd7, 0x8e, 0x72, 0x6c, 0x1e, 0xc0, 0x2b, 0x7e, 0xbf, 0xe9, 0x2b, 0x23, 0xd9, 0xec, 0x34},
        {0xaa, 0xe5, 0x93, 0x9c, 0x8e, 0xfd, 0xf2, 0xf0, 0x4e, 0x60, 0xb9, 0xfe, 0x71, 0x17, 0xb2, 0xc2},
        {0xf0, 0x31, 0xd4, 0xd7, 0x4f, 0x5d, 0xcb, 0xf3, 0x9d, 0xaa, 0xf8, 0xca, 0x3a, 0xf6, 0xe5, 0x27},
        {0x8e, 0xe7, 0x9d, 0xd4, 0xf4, 0x01, 0xff, 0x9b, 0x7e, 0xa9, 0x45, 0xd8, 0x66, 0x66, 0xc1, 0x3b},
        {0x26, 0x29, 0x8e, 0x9c, 0x1d, 0xb5, 0x17, 0xc2, 0x15, 0xfa, 0xdf, 0xb7, 0xd2, 0xa8, 0xd6, 0x91}
    };

    uint8_t a_expected_plain_text[NB_DEC_TESTS][AES_BLOCK_SIZE_BYTES]= {
        {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    };

    for (loop_test=0; loop_test<NB_DEC_TESTS; loop_test++)
    {
        key = a_key[loop_test];
        cipher_text = a_cipher_text[loop_test];
        expected_plain_text = a_expected_plain_text[loop_test];

        res = aes_init(&ctxt, key, AES_KEY_SIZE_BYTES);

        if (res == AES_INIT_SUCCESS)
        {
            res = aes_decrypt_block(&ctxt, cipher_text, plain_text);
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

    printf("\n\n test_decrypt: %u PASS - %u FAIL\n", pass, fail);
}