# AES-128
A basic implementation of AES-128.

## Overview
This implementation does not aim at being optimized nor complete nor secure against attacks.
It is only a basic implementation of AES-128 (ECB, CBC and CTR) which is written 
to be very close to the explanations given in Wikipedia:

https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#High-level_description_of_the_algorithm

The main purpose is to be easy to read and to play around with the AES concepts.

## Architecture
- aes.c implements the core of the AES algorithm (AES ECB)
- aes_cbc.c implements the cipher block chaining mode
- aes_ctr.c implements the counter mode
- aes.h is the API to use this library

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