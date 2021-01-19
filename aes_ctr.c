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
#include <string.h>
#include "aes.h"

/* local macros and defines */
/* ------------------------ */
#define TRACE_ON_CTR 0
#define LOG(fmt, ...) do { if (TRACE_ON_CTR) printf(fmt, __VA_ARGS__); } while(0)


#if defined(AES_CTR)

/* Helper function(s) */
/* ------------------ */

static void do_aes_block_xor_len(uint8_t * out, uint8_t * in, uint8_t len);

static void do_aes_block_xor_len(uint8_t * out, uint8_t * in, uint8_t len)
{
    uint32_t loop=0;

    for (loop=0; ((loop<AES_BLOCK_SIZE_BYTES) && (loop<len)); loop++)
    {
        out[loop] = out[loop] ^ in[loop];
    }
}


/* Exported functions : API */
/* ------------------------ */

uint8_t aes_ctr_init(aes_ctxt_t * ctxt, uint8_t * key, uint8_t key_len, uint8_t * nonce)
{
    uint8_t res = AES_INIT_SUCCESS;
    uint32_t loop=0;

    res = aes_init(ctxt, key, key_len);

    if (res == AES_INIT_SUCCESS)
    {
        if (nonce != NULL)
        {
            /* nonce part */
            memcpy(ctxt->init_vector, nonce, AES_CTR_NONCE_LEN_BYTES);

            /* counter part : set to 0 */
            for (loop=0; loop<AES_CTR_COUNTER_LEN_BYTES; loop++)
            {
                ctxt->init_vector[AES_CTR_NONCE_LEN_BYTES + loop] = 0x00;
            }
        }
        else
        {
            res = AES_INIT_NULL_PTR;
        }
    }

    return(res);
}


uint8_t aes_ctr_encrypt_block(aes_ctxt_t * ctxt, uint8_t * plain_text, uint8_t * cipher_text, uint8_t text_len)
{
    uint8_t cipher_counter[AES_BLOCK_SIZE_BYTES];
    uint8_t res = AES_ENCRYPT_SUCCESS;
    uint32_t counter = 0;
    uint32_t loop=0;
    uint32_t temp = 0;

    /* extract counter */
    for (loop=0; loop<AES_CTR_COUNTER_LEN_BYTES; loop ++)
    {
        temp = (uint32_t)(ctxt->init_vector[AES_CTR_NONCE_LEN_BYTES+loop]);
        temp = temp << (8*(AES_CTR_COUNTER_LEN_BYTES-1-loop));
        counter = counter | temp;
    }

    LOG("\nCounter: %u\n", counter);

    /* encrypt counter */
    res = aes_encrypt_block(ctxt, ctxt->init_vector, cipher_counter);

    /* plain_text ^ encrypted counter */
    /* ------------------------------ */
    /* Initialize cipher_text with plain_text */
    if (cipher_text != plain_text)
    {
        memcpy(cipher_text, plain_text, text_len);
    }
    /* else : encrypt in place */

    /* do the xor */
    do_aes_block_xor_len(cipher_text, cipher_counter, text_len);

    /* update counter for next block */
    if (counter<UINT32_MAX)
    {
        counter ++;
    }
    else
    {
        LOG("\nCounter wrap-around, should change the nonce: %u\n", counter);
        counter = 0;
    }

    for (loop=0; loop<AES_CTR_COUNTER_LEN_BYTES; loop ++)
    {
        temp = counter >> (8*(AES_CTR_COUNTER_LEN_BYTES-1-loop));
        ctxt->init_vector[AES_CTR_NONCE_LEN_BYTES+loop] = temp;
    }

    return(res);
}


uint8_t aes_ctr_decrypt_block(aes_ctxt_t * ctxt, uint8_t * cipher_text,  uint8_t * plain_text, uint8_t text_len)
{
    uint8_t cipher_counter[AES_BLOCK_SIZE_BYTES];
    uint8_t res = AES_DECRYPT_SUCCESS;
    uint32_t counter = 0;
    uint32_t loop=0;
    uint32_t temp = 0;    

    /* extract counter */
    for (loop=0; loop<AES_CTR_COUNTER_LEN_BYTES; loop ++)
    {
        temp = (uint32_t)(ctxt->init_vector[AES_CTR_NONCE_LEN_BYTES+loop]);
        temp = temp << (8*(AES_CTR_COUNTER_LEN_BYTES-1-loop));
        counter = counter | temp;
    }

    LOG("\nCounter: %u\n", counter);

    /* encrypt counter */
    res = aes_encrypt_block(ctxt, ctxt->init_vector, cipher_counter);

    /* cipher_text ^ encrypted counter */
    /* ------------------------------- */
    /* Initialize plain_text with cipher_text */
    if (cipher_text != plain_text)
    {
        memcpy(plain_text, cipher_text, text_len);
    }
    /* else : decrypt in place */

    /* do the xor */
    do_aes_block_xor_len(plain_text, cipher_counter, text_len);    

    /* update counter for next block */
    if (counter<UINT32_MAX)
    {
        counter ++;
    }
    else
    {
        LOG("\nCounter wrap-around, should change the nonce: %u\n", counter);
        counter = 0;
    }

    for (loop=0; loop<AES_CTR_COUNTER_LEN_BYTES; loop ++)
    {
        temp = counter >> (8*(AES_CTR_COUNTER_LEN_BYTES-1-loop));
        ctxt->init_vector[AES_CTR_NONCE_LEN_BYTES+loop] = temp;
    }    

    return(res);
}

#endif /* AES_CTR */