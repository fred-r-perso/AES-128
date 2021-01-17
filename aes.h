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
#ifndef AES_H
#define AES_H

#include <stdint.h>

#define AES_KEY_SIZE_BYTES (16U)          /* AES-128 only : 128 bits so 16 bytes */
#define AES_EXPANDED_KEY_SIZE_WORD (44U) /* AES-128 only : initial round + 10 rounds so 11 * 4 words */
#define AES_BLOCK_SIZE_BYTES (16U) /* each AES block is 16 bytes */

typedef struct {
    uint32_t expKey[AES_EXPANDED_KEY_SIZE_WORD]; /* expanded key */
} aes_ctxt_t;

/*
 * Initialize the AES-128 system
 * param ctxt: context to be allocated by the caller [out]
 * param key : AES-128 key [in]
 * param key_len : key length, should be 16 (AES-128) [in]
 * return : 0 for success, >0 otherwise
 */
uint8_t aes_init(aes_ctxt_t * ctxt, uint8_t * key, uint8_t key_len);
/* return values */
#define AES_INIT_SUCCESS       (0U)  /* init is successful */
#define AES_INIT_NULL_PTR      (1U)  /* one input pointer is NULL */
#define AES_INIT_NOT_SUPPORTED (2U)  /* unsupported key length: AES-128 only */

/*
 * Encrypt a block
 * param ctxt : current context, previously initialized with aes_init [in]
 * param plain_text : input buffer to be encrypted (16 bytes, You should pad the end of the buffer with zeros if this is not the case) [in]
 * param cipher_text : output buffer with ciphertext, allocated by the caller (16 bytes) [out]
 * return : 0 for success, >0 otherwise
 */
uint8_t aes_encrypt_block(aes_ctxt_t * ctxt, uint8_t * plain_text, uint8_t * cipher_text);
#define AES_ENCRYPT_SUCCESS  (0U)  /* block encrypted successfully */
#define AES_ENCRYPT_NULL_PTR (1U)  /* one input pointer is NULL */


#endif /* AES_H */