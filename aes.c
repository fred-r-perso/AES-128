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
#include "gf256.h"

/* AES128 only */
#define KEY_LEN_WORDS (4U)   /* 4 uint32_t = 4 words */
#define NB_KEY_ROUNDS (10U)  /* Initial round key addition + 10 key rounds for AES-128 */

/* Encrypt or decrypt mode */
#define DIRECTION_ENCRYPT (0U) /* use a function in encrypt mode */
#define DIRECTION_DECRYPT (1U) /* use a function in decrypt mode */

/* private functions prototypes */
/* ---------------------------- */
static inline uint8_t get_sbox_value(uint8_t x);
static inline uint8_t get_inverse_sbox_value(uint8_t x);
/* not static for unit tests */
uint32_t RotWord(uint32_t k); 
uint32_t SubWord(uint32_t k);
void KeyExpansion(uint32_t * expandedKey, uint32_t * key);
void getRoundKey(uint32_t * expandedKey, uint8_t * roundKey, uint8_t round);
void initialRound(uint8_t * text, uint8_t * roundKey);
/* the AddRoundKey is the same code as initialRound */
#define AddRoundKey(text, key) initialRound(text, key)
void SubBytes(uint8_t * text, uint8_t direction);
void ShiftRows(uint8_t * text);
void InvShiftRows(uint8_t * text);
void do_mult(uint8_t * column, const uint8_t * matrix);
void MixColumns(uint8_t * text, uint8_t direction);

/* local macros and defines */
/* ------------------------ */
#define TRACE_ON 0
#define LOG(fmt, ...) do { if (TRACE_ON) printf(fmt, __VA_ARGS__); } while(0)

/* Rijndael S-box */
/* -------------- */
/* 
 * see: https://en.wikipedia.org/wiki/Rijndael_S-box 
 * The column is determined by the least significant nibble, and the row by the most significant nibble.
 * This means that we can access the S-box like an array though we present it as a 16 * 16 matrix.
 * Example : 0x1A => column A and row 1 and 0x14 = 26 so we can access the element at index 26 of the array: 0xa2.
 */
static const uint8_t aes_sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
};

static const uint8_t aes_inverse_sbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* getter for S-box */
static inline uint8_t get_sbox_value(uint8_t x)
{
    return aes_sbox[x];
}

/* getter for inverse S-box */
static inline uint8_t get_inverse_sbox_value(uint8_t x)
{
    return aes_inverse_sbox[x];
}

/* Fixed matrix in GF(256) for MixColumns */
/* -------------------------------------- */
/* not static for unit tests */
const uint8_t MixColumns_Matrix[16] = { 
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02
};

/* reverse matrix */
const uint8_t InvMixColumns_Matrix[16] = {
    0x0e, 0x0b, 0x0d, 0x09,
    0x09, 0x0e, 0x0b, 0x0d,
    0x0d, 0x09, 0x0e, 0x0b,
    0x0b, 0x0d, 0x09, 0x0e
};

/* Key expansion */
/* ------------- */
/* 
 * See: https://en.wikipedia.org/wiki/AES_key_schedule 
 * To match the wikipedia explanations we work with words.
 * So the base element for key expansion is uint32_t. 
 */

/* rcon : rcon[i] = rcon[i-1]*2 in GF(256) */
/* rcon(i) = [rc(i) 00 00 00]              */
static const uint32_t rcon[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000};

/* define RotWord as a one-byte left circular shift*/
uint32_t RotWord(uint32_t k)
{
    /* k0 k1 k2 k3 becomes k1 k2 k3 k0 */
    uint8_t k0 = (uint8_t)(k>>24);
    uint32_t res = k << 8;
    
    res = res | k0;
    return(res);
}

/*define SubWord as an application of the AES S-box to each of the four bytes of the word */
uint32_t SubWord(uint32_t k)
{
    uint32_t res = 0;
    uint32_t loop = 0;
    uint8_t byte = 0;

    /* substitute each byte */
    for (loop=0; loop<4; loop++)
    {
        byte = (uint8_t)((k>>(8*loop)) & 0x000000FF);
        res = res | ((uint32_t)(get_sbox_value(byte)<<8*loop));
    }

    return(res);
}

/* Key expansion algorithm as per wikipedia */
/* uint32_t expandedKey[NB_KEY_ROUNDS*KEY_LEN_WORDS] : 44bytes for AES-128 */
void KeyExpansion(uint32_t * expandedKey, uint32_t * key)
{
    uint32_t previous = 0;
    uint32_t loop = 0;

    /* 
     * AES-128 : loop on the 44 words of the expanded key 
     * Initial key (round 0)+ 10 round keys (rounds 1 to 10) = 1+NB_KEY_ROUNDS = 11
     */
    for (loop=0; loop<(NB_KEY_ROUNDS+1)*KEY_LEN_WORDS; loop++)
    {
        /* AES-128 : the 16 first bytes (4 words) are the key itself */
        if (loop<KEY_LEN_WORDS)
        {
            /* take the value as is */   
            expandedKey[loop] = key[loop];
        }
        else if (loop>=KEY_LEN_WORDS)
        {
            /* We have a previous value */
            previous = expandedKey[loop-1]; 

            /* 
             * AES-128 : if we have loop = 0 mod KEY_LEN_WORDS
             * WATCH OUT : for AES-192 and 256 we would have to check the other condition from WIkipedia,
             *             loop = 4 mod KEY_LEN_WORDS, but for AES-128 it disappears
             */
            if (loop % KEY_LEN_WORDS == 0)
            {
                /* 
                 * We need to apply the following steps (see Wikipedia): 
                 * 1. SubWord(RotWord(previous)) ^ rcon[loop/KEY_LEN_WORDS] 
                 * 2. result of (1) ^ previous
                 * 3. result of (2) ^ expandedKey[loop - KEY_LEN_WORDS]
                 */
                LOG("\nprevious: %08x\n", previous);
                previous = RotWord(previous);
                LOG("RotWord: %08x\n", previous);
                previous = SubWord(previous);
                LOG("SubWord: %08x\n", previous);
                previous = previous ^ rcon[loop/KEY_LEN_WORDS -1];
                LOG("rcon: %08x\n", previous);
                /* Last step (3) done in the common part */
            }
            
            /* update expanded key in all cases */
            expandedKey[loop] = expandedKey[loop - KEY_LEN_WORDS] ^ previous;
        }

    }
}

/* 
 * For the implementation of the AES algorithm as described in:
 *     https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#High-level_description_of_the_algorithm
 * we use bytes so we need to convert the key in an array of bytes.
 *
 */
void getRoundKey(uint32_t * expandedKey, uint8_t * roundKey, uint8_t round)
{
    uint32_t * curKey;
    uint32_t loop = 0;
    uint8_t position = round*KEY_LEN_WORDS; /* starting with round = 0 is initial round key addition then 10 rounds */

    curKey = &expandedKey[position];

    /* loop on each word of the round key (4 words in total) */
    for (loop=0; loop<KEY_LEN_WORDS; loop++)
    {
        /* extract each byte of each word : 4 bytes */
        roundKey[loop*KEY_LEN_WORDS] = (curKey[loop] & 0xFF000000)>>24;
        roundKey[loop*KEY_LEN_WORDS + 1] = (curKey[loop] & 0x00FF0000)>>16;
        roundKey[loop*KEY_LEN_WORDS + 2] = (curKey[loop] & 0x0000FF00)>>8;
        roundKey[loop*KEY_LEN_WORDS + 3] = curKey[loop] & 0x000000FF;
    }

}

/* Initial round */
/* ------------- */
/* 
 * AddRoundKey – 
 * each byte of the state is combined with a byte of the round key using bitwise xor.
 */
void initialRound(uint8_t * text, uint8_t * roundKey)
{
    uint32_t loop = 0;

    for (loop=0; loop<AES_BLOCK_SIZE_BYTES; loop++)
    {
        /* the input plain text is updated */
        text[loop] = text[loop] ^ roundKey[loop];
    }
}

/* Rounds 1 to 10 */
/* -------------- */
/*
 * After initial round (round 0, see above)
 *
 * Encrypt:
 *   SubBytes – a non-linear substitution step where each byte is replaced with another according to a lookup table.
 *   ShiftRows – a transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
 *   MixColumns – a linear mixing operation which operates on the columns of the state, combining the four bytes in each column.
 *   AddRoundKey
 *   Round 10 is different : the MixColumns is not used
 *
 * Decrypt:
 *   InvShiftRows
 *   InvSubBytes
 *   AddRoundKey
 *   InvMixColumns
 *   Round 10 is different : the InvMixColumns is not used
 *
 */
void SubBytes(uint8_t * text, uint8_t direction)
{
    uint32_t loop=0;

    for (loop=0; loop<AES_BLOCK_SIZE_BYTES; loop++)
    {
        if (direction == DIRECTION_ENCRYPT)
        {
          text[loop] = get_sbox_value(text[loop]);
        }
        else
        {
          /* InvSubBytes */
         text[loop] = get_inverse_sbox_value(text[loop]); 
        }
    }
}


void ShiftRows(uint8_t * text)
{
    uint32_t loop_row;
    uint32_t loop;
    uint8_t temp;
    uint8_t row[4];

    /* 
     * AES operates on a 4 × 4 column-major order array of bytes, termed the state.
     * So in memory, the consecutive bytes are the columns.
     * A column is: text[0] text[1] text[2] text[3] ...etc for next columns...
     * So a row is text[0] text[4] text[8] text[12] ...etc for next rows...
     */

    /* No change for the first row so loop=0 is skipped */
    for (loop_row=1; loop_row<4; loop_row++)
    {
        /* Recreate the row in consecutive memory slots */
        row[0] = text[loop_row];
        row[1] = text[loop_row+4];
        row[2] = text[loop_row+8];
        row[3] = text[loop_row+12];

        if (loop_row==1)
        {
            /* Shift left by offset of 1*/
            temp = row[0];

            for (loop=0; loop<3; loop++)
            {
                row[loop] = row[loop+1];
            }

            row[3] = temp;
        }
        else if (loop_row==2)
        {
            /* Shift left by offset of 2 */
            temp = row[0];
            row[0] = row[2];
            row[2] = temp;
            temp = row[1];
            row[1] = row[3];
            row[3] = temp;
        }
        else
        {
            /* 
             * loop_row=3 
             * Shift left by offset of 3 is the same as a shift right by offset of 1
             */   
            temp=row[3];

            for (loop=3; loop>0; loop--)
            {
                row[loop] = row[loop-1];
            }

            row[0] = temp;
        }

        /* Update the text to have the representation in column-major order */
        text[loop_row] = row[0];
        text[loop_row+4] = row[1];
        text[loop_row+8] = row[2];
        text[loop_row+12] = row[3];        
    }
}


/* Create a separate function for the sake of legibility */
void InvShiftRows(uint8_t * text)
{
    uint32_t loop_row;
    uint32_t loop;
    uint8_t temp;
    uint8_t row[4];

    /* 
     * AES operates on a 4 × 4 column-major order array of bytes, termed the state.
     * So in memory, the consecutive bytes are the columns.
     * A column is: text[0] text[1] text[2] text[3] ...etc for next columns...
     * So a row is text[0] text[4] text[8] text[12] ...etc for next rows...
     */

    /* No change for the first row so loop=0 is skipped */
    for (loop_row=1; loop_row<4; loop_row++)
    {
        /* Recreate the row in consecutive memory slots */
        row[0] = text[loop_row];
        row[1] = text[loop_row+4];
        row[2] = text[loop_row+8];
        row[3] = text[loop_row+12];

        if (loop_row==1)
        {
            /* Shift right by offset of 1*/
            temp=row[3];

            for (loop=3; loop>0; loop--)
            {
                row[loop] = row[loop-1];
            }

            row[0] = temp;          
        }
        else if (loop_row==2)
        {
            /* Shift right by offset of 2 */
            temp = row[2];
            row[2] = row[0];
            row[0] = temp;
            temp = row[3];
            row[3] = row[1];
            row[1] = temp;
        }
        else
        {
            /* 
             * loop_row=3 
             * Shift right by offset of 3 is the same as a shift left by offset of 1
             */   
            temp = row[0];

            for (loop=0; loop<3; loop++)
            {
                row[loop] = row[loop+1];
            }

            row[3] = temp;
        }

        /* Update the text to have the representation in column-major order */
        text[loop_row] = row[0];
        text[loop_row+4] = row[1];
        text[loop_row+8] = row[2];
        text[loop_row+12] = row[3];        
    }
}


void do_mult(uint8_t * column, const uint8_t * matrix)
{
    uint32_t outer_loop=0;
    uint32_t inner_loop=0;
    uint8_t res_vect[4];

    /* initialize res_vect */
    memset(res_vect, 0x00, 4*sizeof(uint8_t));

    /* Multiply the column by the matrix */
    for (outer_loop=0; outer_loop<4; outer_loop++)
    {
        /* For each row of the matrix */
        for (inner_loop=0; inner_loop<4; inner_loop++)
        {
            /* 
             * For each coefficient of the column
             * Multiply the coeeficient of the column by the coefficient of the matrix in GF(256)
             * Add this result to the result of the previous round 
             */
            res_vect[outer_loop] = add_poly(res_vect[outer_loop],mult_poly(column[inner_loop], matrix[outer_loop*4+inner_loop]));
        }
    }

    /* Update the input */
    memcpy(column, res_vect, 4);
}


void MixColumns(uint8_t * text, uint8_t direction)
{
    uint32_t loop=0;
    uint8_t column[4];
    /* 
     * AES operates on a 4 × 4 column-major order array of bytes, termed the state.
     * So in memory, the consecutive bytes are the columns.
     * A column is: text[0] text[1] text[2] text[3] ...etc for next columns...
     */

    /* we have 4 columns */
    for (loop=0; loop<4; loop ++)
    {
        /* extract column */
        column[0] = text[loop*4];
        column[1] = text[loop*4+1];
        column[2] = text[loop*4+2];
        column[3] = text[loop*4+3];

        if (direction == DIRECTION_ENCRYPT)
        {
          /* 
          * Encrypt: Multiply the column by MixColumns_Matrix in GF(256) 
          * The column is updated.
          */
          do_mult(column, MixColumns_Matrix);
        }
        else
        {
          /* Decrypt : InvMixColumns */
         do_mult(column, InvMixColumns_Matrix); 
        }

        /* Update the input text */
        text[loop*4] = column[0];
        text[loop*4+1] = column[1];
        text[loop*4+2] = column[2];
        text[loop*4+3] = column[3];
    }
}


/* Exported functions : API */
/* ------------------------ */
uint8_t aes_init(aes_ctxt_t * ctxt, uint8_t * key, uint8_t key_len)
{
    uint8_t res = AES_INIT_SUCCESS;

    if ( (ctxt == NULL) || (key == NULL) )
    {
        res = AES_INIT_NULL_PTR;
    }

    if (key_len != AES_KEY_SIZE_BYTES)
    {
        /* Only AES-128 is supported */
        res = AES_INIT_NOT_SUPPORTED;
    }

    if (res == AES_INIT_SUCCESS)
    {
        /* Convert the input key in 4 words */
        uint32_t word_key[KEY_LEN_WORDS];

        word_key[0] = key[0]<<24|key[1]<<16|key[2]<<8|key[3];
        word_key[1] = key[4]<<24|key[5]<<16|key[6]<<8|key[7];
        word_key[2] = key[8]<<24|key[9]<<16|key[10]<<8|key[11];
        word_key[3] = key[12]<<24|key[13]<<16|key[14]<<8|key[15];

        LOG("\nkey: %08x %08x %08x %08x\n", word_key[0], word_key[1], word_key[2], word_key[3]);

        /* Compute expanded key */
        KeyExpansion(ctxt->expKey, word_key);
    }

    return(res);
}


uint8_t aes_encrypt_block(aes_ctxt_t * ctxt, uint8_t * plain_text, uint8_t * cipher_text)
{
    uint8_t res = AES_ENCRYPT_SUCCESS;
    uint8_t roundKey[AES_KEY_SIZE_BYTES];

    if ( (ctxt == NULL) || (plain_text == NULL) || (cipher_text == NULL) )
    {
        res = AES_ENCRYPT_NULL_PTR;
    } 
    else
    {
        uint32_t round=0;
        /*
         * AES operates on a 4 × 4 column-major order array of bytes, termed the state.
         * The bytes are represented by a 4*4 matrix ordered like this:
         *     b0 b4 b8  b12
         *     b1 b5 b9  b13
         *     b2 b6 b10 b14
         *     b3 b7 b11 b15
         * See https://en.wikipedia.org/wiki/Row-_and_column-major_order
         * Column-major order means in memory:
         *     b0, b1, b2, b3 ...etc...
         */

        /* Initialize cipher_text with plain_text */
        if (cipher_text != plain_text)
        {
            memcpy(cipher_text, plain_text, AES_BLOCK_SIZE_BYTES);
        }
        /* else : encrypt in place */

        if (res == AES_ENCRYPT_SUCCESS)
        {
            /* Get first round key : index 0*/
            getRoundKey(ctxt->expKey, roundKey, round);

            /* Initial round key addition (round 0 is not part of the 10 AES-128 rounds) */
            initialRound(cipher_text, roundKey);

            LOG("\nafter initial round: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", 
                cipher_text[0], cipher_text[1], cipher_text[2], cipher_text[3], 
                cipher_text[4], cipher_text[5], cipher_text[6], cipher_text[7],
                cipher_text[8], cipher_text[9], cipher_text[10], cipher_text[11], 
                cipher_text[12], cipher_text[13], cipher_text[14], cipher_text[15]);

            /* Start repeating rounds from round 1 to round 10 */
            round ++;

            /* AES-128 : 9 rounds with full processing + 1 last round (1 to 10) */
            while (round <= NB_KEY_ROUNDS)
            {
                LOG("round %u input: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", round,
                    cipher_text[0], cipher_text[1], cipher_text[2], cipher_text[3], 
                    cipher_text[4], cipher_text[5], cipher_text[6], cipher_text[7],
                    cipher_text[8], cipher_text[9], cipher_text[10], cipher_text[11], 
                    cipher_text[12], cipher_text[13], cipher_text[14], cipher_text[15]);

                /* sub bytes */
                SubBytes(cipher_text, DIRECTION_ENCRYPT);

                LOG("round %u SubBytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", round,
                    cipher_text[0], cipher_text[1], cipher_text[2], cipher_text[3], 
                    cipher_text[4], cipher_text[5], cipher_text[6], cipher_text[7],
                    cipher_text[8], cipher_text[9], cipher_text[10], cipher_text[11], 
                    cipher_text[12], cipher_text[13], cipher_text[14], cipher_text[15]);

                /* shift rows */
                ShiftRows(cipher_text);

                LOG("round %u ShiftRows: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", round, 
                    cipher_text[0], cipher_text[1], cipher_text[2], cipher_text[3], 
                    cipher_text[4], cipher_text[5], cipher_text[6], cipher_text[7],
                    cipher_text[8], cipher_text[9], cipher_text[10], cipher_text[11], 
                    cipher_text[12], cipher_text[13], cipher_text[14], cipher_text[15]);


                /* last round : no mix columns */
                if (round != NB_KEY_ROUNDS)
                {
                    /* Not Round 10 */
                    MixColumns(cipher_text, DIRECTION_ENCRYPT);

                    LOG("round %u MixColumns: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", round, 
                        cipher_text[0], cipher_text[1], cipher_text[2], cipher_text[3], 
                        cipher_text[4], cipher_text[5], cipher_text[6], cipher_text[7],
                        cipher_text[8], cipher_text[9], cipher_text[10], cipher_text[11], 
                        cipher_text[12], cipher_text[13], cipher_text[14], cipher_text[15]);

                }
                /* else round 10: skip MixColumns */

                /* add round key */
                getRoundKey(ctxt->expKey, roundKey, round);
                AddRoundKey(cipher_text, roundKey);

                LOG("round %u AddRoundKey: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", round, 
                    cipher_text[0], cipher_text[1], cipher_text[2], cipher_text[3], 
                    cipher_text[4], cipher_text[5], cipher_text[6], cipher_text[7],
                    cipher_text[8], cipher_text[9], cipher_text[10], cipher_text[11], 
                    cipher_text[12], cipher_text[13], cipher_text[14], cipher_text[15]);                

                round ++;
            }
        }
    }

    return(res);
}


uint8_t aes_decrypt_block(aes_ctxt_t * ctxt, uint8_t * cipher_text, uint8_t * plain_text)
{
    uint8_t res = AES_DECRYPT_SUCCESS;
    uint8_t roundKey[AES_KEY_SIZE_BYTES];

    if ( (ctxt == NULL) || (plain_text == NULL) || (cipher_text == NULL) )
    {
        res = AES_DECRYPT_NULL_PTR;
    } 
    else
    {
        uint32_t round=0;

        /* Initialize plain_text with cipher_text */
        if (cipher_text != plain_text)
        {
            memcpy(plain_text, cipher_text, AES_BLOCK_SIZE_BYTES);
        }
        /* else : decrypt in place */

        if (res == AES_DECRYPT_SUCCESS)
        {
            /* Get last round key for decrypt */
            getRoundKey(ctxt->expKey, roundKey, NB_KEY_ROUNDS-round);

            /* Initial round key addition (round=0) : take the last round key for decrypt */
            initialRound(plain_text, roundKey);

            LOG("\nafter initial round: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", 
                plain_text[0], plain_text[1], plain_text[2], plain_text[3], 
                plain_text[4], plain_text[5], plain_text[6], plain_text[7],
                plain_text[8], plain_text[9], plain_text[10], plain_text[11], 
                plain_text[12], plain_text[13], plain_text[14], plain_text[15]);

            /* Start repeating rounds from round 1 */
            round ++;

            /* AES-128 : 9 rounds with full processing + 1 last round (1 to 10) */
            while (round <= NB_KEY_ROUNDS)
            {
                LOG("round %u input: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", round,
                    plain_text[0], plain_text[1], plain_text[2], plain_text[3], 
                    plain_text[4], plain_text[5], plain_text[6], plain_text[7],
                    plain_text[8], plain_text[9], plain_text[10], plain_text[11], 
                    plain_text[12], plain_text[13], plain_text[14], plain_text[15]);

                /* reverse shift rows */
                InvShiftRows(plain_text);

                LOG("round %u InvShiftRows: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", round, 
                    plain_text[0], plain_text[1], plain_text[2], plain_text[3], 
                    plain_text[4], plain_text[5], plain_text[6], plain_text[7],
                    plain_text[8], plain_text[9], plain_text[10], plain_text[11], 
                    plain_text[12], plain_text[13], plain_text[14], plain_text[15]);


                /* sub bytes */
                SubBytes(plain_text, DIRECTION_DECRYPT);

                LOG("round %u InvSubBytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", round,
                    plain_text[0], plain_text[1], plain_text[2], plain_text[3], 
                    plain_text[4], plain_text[5], plain_text[6], plain_text[7],
                    plain_text[8], plain_text[9], plain_text[10], plain_text[11], 
                    plain_text[12], plain_text[13], plain_text[14], plain_text[15]);

                /* add round key */
                getRoundKey(ctxt->expKey, roundKey, NB_KEY_ROUNDS-round);
                AddRoundKey(plain_text, roundKey);

                LOG("round %u AddRoundKey: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", round, 
                    plain_text[0], plain_text[1], plain_text[2], plain_text[3], 
                    plain_text[4], plain_text[5], plain_text[6], plain_text[7],
                    plain_text[8], plain_text[9], plain_text[10], plain_text[11], 
                    plain_text[12], plain_text[13], plain_text[14], plain_text[15]);                

                /* last round : no mix columns */
                if (round != NB_KEY_ROUNDS)
                {
                    MixColumns(plain_text, DIRECTION_DECRYPT);

                    LOG("round %u InvMixColumns: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", round, 
                        plain_text[0], plain_text[1], plain_text[2], plain_text[3], 
                        plain_text[4], plain_text[5], plain_text[6], plain_text[7],
                        plain_text[8], plain_text[9], plain_text[10], plain_text[11], 
                        plain_text[12], plain_text[13], plain_text[14], plain_text[15]);

                }

                round ++;
            }            
        }
    }

    return(res);
}