# AES-128
A basic implementation of AES-128.

## Overview
This implementation does not aim at being optimized nor complete nor secure against attacks.
It is only a basic implementation of AES-128 (ECB, CBC and CTR) which is written 
to be very close to the explanations given in Wikipedia:

https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#High-level_description_of_the_algorithm

The main purpose is to be easy to read and to play around with the AES concepts.

## Architecture

### Files organization
- aes.c implements the core of the AES algorithm (AES ECB)
- aes_cbc.c implements the cipher block chaining mode
- aes_ctr.c implements the counter mode
- aes.h is the API to use this library

### Data
The library works with a context allocated by the caller.  
The structrure is: aes_ctxt_t.

### Dynamic behavior
1. Allocate a context
2. Call aes_XXX_init() to initialize the context.
3. Call aes_XXX_encrypt/decrypt_block() to process a block.

## Artefacts
If you use 'make all'
- libaes.a is the library
- aestest is the test program

## Platform
Developed and tested on:
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.5 LTS
Release:    18.04
Codename:   bionic

## Build-time options
- AES_CBC : enables the support of CBC mode of operation 
- AES_CTR : enables the support of CTR mode of operation
- LOOKUP_GF256 : use lookup tables to do the galois multiplications in GF(256)

If LOOKUP_GF256 is disabled then libgf256 is required to implement the arithmetics in GF(256).  
See: https://github.com/fred-r/GF256  
Library for Ubuntu (.a) provided in libgf256 folder. 

## Codesize
Figures for an x86 64 bits with Ubuntu 18.04.5 LTS.  

- With LOOKUP_GF256 enabled:
> Using "size libaes.a"  
   text    data     bss     dec     hex filename  
    610       0       0     610     262 aes_cbc.o (ex libaes.a)  
   6709       0       0    6709    1a35 aes.o (ex libaes.a)  
   1090       0       0    1090     442 aes_ctr.o (ex libaes.a)  


