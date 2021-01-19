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

#include <string.h>
#include "aes.h"

#if defined(AES_CBC)



/* Helper function(s) */
/* ------------------ */

static void do_aes_block_xor(uint8_t * out, uint8_t * in);

static void do_aes_block_xor(uint8_t * out, uint8_t * in)
{
    uint32_t loop=0;

    for (loop=0; loop<AES_BLOCK_SIZE_BYTES; loop++)
    {
        out[loop] = out[loop] ^ in[loop];
    }
}


/* Exported functions : API */
/* ------------------------ */

uint8_t aes_cbc_init(aes_ctxt_t * ctxt, uint8_t * key, uint8_t key_len, uint8_t * iv)
{
    uint8_t res = AES_INIT_SUCCESS;

    res = aes_init(ctxt, key, key_len);

    if (res == AES_INIT_SUCCESS)
    {
        if (iv != NULL)
        {
            memcpy(ctxt->init_vector, iv, AES_BLOCK_SIZE_BYTES);
        }
        else
        {
            res = AES_INIT_NULL_PTR;
        }
    }

    return(res);
}


uint8_t aes_cbc_encrypt_block(aes_ctxt_t * ctxt, uint8_t * plain_text, uint8_t * cipher_text)
{
    uint8_t res = AES_ENCRYPT_SUCCESS;

    /* Initialize cipher_text with plain_text */
    if (cipher_text != plain_text)
    {
        memcpy(cipher_text, plain_text, AES_BLOCK_SIZE_BYTES);
    }
    /* else : encrypt in place */

    /* IV xor plain_text */
    do_aes_block_xor(cipher_text, ctxt->init_vector);

    /* AES encryption : cipher_text contains the xored plain_text */
    res = aes_encrypt_block(ctxt, cipher_text, cipher_text);

    if (res == AES_ENCRYPT_SUCCESS)
    {
        /* Update IV with ciphertext for next round */
        memcpy(ctxt->init_vector, cipher_text, AES_BLOCK_SIZE_BYTES);
    }

    return(res);
}


uint8_t aes_cbc_decrypt_block(aes_ctxt_t * ctxt, uint8_t * cipher_text, uint8_t * plain_text)
{
    uint8_t res = AES_DECRYPT_SUCCESS;

    /* AES decryption */
    res = aes_decrypt_block(ctxt, cipher_text, plain_text);

    if (res == AES_DECRYPT_SUCCESS)
    {
        /* xor between IV and plain_text */
        do_aes_block_xor(plain_text, ctxt->init_vector);

        /* Update IV with ciphertext for next round */
        memcpy(ctxt->init_vector, cipher_text, AES_BLOCK_SIZE_BYTES);
    }    

    return(res);

}

#endif /* AES_CBC */