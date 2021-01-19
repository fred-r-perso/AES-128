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

/* AES-128 context */
typedef struct {
    uint32_t expKey[AES_EXPANDED_KEY_SIZE_WORD]; /* expanded key */
#if defined(AES_CBC) || defined(AES_CTR)
    uint8_t init_vector[AES_BLOCK_SIZE_BYTES];   /* IV at initialisation, then previous cipher block */
#endif /* AES_CBC || AES_CTR */    
} aes_ctxt_t;


/* AES (ECB) basic API */
/* ------------------- */

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

/*
 * Decrypt a block
 * param ctxt : current context, previously initialized with aes_init [in]
 * param cipher_text : input buffer to be decrypted (16 bytes) [in]
 * param plain_text : output buffer with plain text, allocated by the caller (16 bytes) [out]
 * return : 0 for success, >0 otherwise
 */
uint8_t aes_decrypt_block(aes_ctxt_t * ctxt, uint8_t * cipher_text, uint8_t * plain_text);
#define AES_DECRYPT_SUCCESS  (0U)  /* block encrypted successfully */
#define AES_DECRYPT_NULL_PTR (1U)  /* one input pointer is NULL */

/* Mode(s) of operation */
/* -------------------- */

/* CBC */
#if defined(AES_CBC)
/*
 * Initialize the AES-128 system for CBC mode of operation
 * param ctxt: context to be allocated by the caller [out]
 * param key : AES-128 key [in]
 * param key_len : key length, should be 16 (AES-128) [in]
 * param iv : initialization vector [in]
 * return : 0 for success, >0 otherwise
 */
uint8_t aes_cbc_init(aes_ctxt_t * ctxt, uint8_t * key, uint8_t key_len, uint8_t * iv);

/*
 * Encrypt a block in CBC mode of operation
 * param ctxt : current context, previously initialized with aes_init [in]
 * param plain_text : input buffer to be encrypted (16 bytes, You should pad the end of the buffer with zeros if this is not the case) [in]
 * param cipher_text : output buffer with ciphertext, allocated by the caller (16 bytes) [out]
 * return : 0 for success, >0 otherwise
 */
uint8_t aes_cbc_encrypt_block(aes_ctxt_t * ctxt, uint8_t * plain_text, uint8_t * cipher_text);

/*
 * Decrypt a block in CBC mode of operation
 * param ctxt : current context, previously initialized with aes_init [in]
 * param cipher_text : input buffer to be decrypted (16 bytes) [in]
 * param plain_text : output buffer with plain text, allocated by the caller (16 bytes) [out]
 * return : 0 for success, >0 otherwise
 */
uint8_t aes_cbc_decrypt_block(aes_ctxt_t * ctxt, uint8_t * cipher_text, uint8_t * plain_text);

#endif /* AES_CBC */

/* CTR */

#if defined(AES_CTR)

/*
 * As long as the key remains the same:
 *   - the nonce must be updated for each message (and not repeated for the same key)
 *   - the counter is incremented for each block of the message
 */
#define AES_CTR_NONCE_LEN_BYTES (12U) /* 12 bytes for nonce and 4 bytes for counter */
#define AES_CTR_COUNTER_LEN_BYTES (AES_BLOCK_SIZE_BYTES - AES_CTR_NONCE_LEN_BYTES)

/*
 * Initialize the AES-128 system for CBC mode of operation
 * param ctxt: context to be allocated by the caller [out]
 * param key : AES-128 key [in]
 * param key_len : key length, should be 16 (AES-128) [in]
 * param nonce : 96-bit nonce [in]
 * return : 0 for success, >0 otherwise
 *
 * The counter must never be the same for 2 messages or for 2 blocks within the same message.
 * To do so we build our counter by concatenating a nonce and a counter.
 * The nonce is a 96-bit value that must be updated each time a new message is encrypted with the same key.
 * The nonce remains the same for all the blocks of a message.
 * It is concatenated with a 32 bit counter incremented for each processed block.
 * [128_bit ctr counter] = [96-bit nonce] || [32-bit counter]
 * This library can process with the same key: 2pow96 messages and each message can contain 2pow32 blocks.
 *
 * Implementation choice: as on wikipedia the counter starts from 0, we have decided to start the counter from 0.
 * See: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
 * But be careful, some specs start from 1. 
 */
uint8_t aes_ctr_init(aes_ctxt_t * ctxt, uint8_t * key, uint8_t key_len, uint8_t * nonce);

/*
 * Encrypt a block in CTR mode of operation
 * param ctxt : current context, previously initialized with aes_init [in]
 * param plain_text : input buffer to be encrypted (16 bytes or less) [in]
 * param cipher_text : output buffer with ciphertext, allocated by the caller (16 bytes or less) [out]
 * param text_len : number of bytes to be processed in the block (max. 16 bytes) [in]
 * return : 0 for success, >0 otherwise
 */
uint8_t aes_ctr_encrypt_block(aes_ctxt_t * ctxt, uint8_t * plain_text, uint8_t * cipher_text, uint8_t text_len);

/*
 * Decrypt a block in CTR mode of operation
 * param ctxt : current context, previously initialized with aes_init [in]
 * param cipher_text : input buffer to be decrypted (16 bytes or less) [in]
 * param plain_text : output buffer with plain text, allocated by the caller (16 bytes or less) [out]
 * param text_len : number of bytes to be processed in the block (max. 16 bytes) [in]
 * return : 0 for success, >0 otherwise
 */
uint8_t aes_ctr_decrypt_block(aes_ctxt_t * ctxt, uint8_t * cipher_text,  uint8_t * plain_text, uint8_t text_len);

#endif /* AES_CTR */

#endif /* AES_H */