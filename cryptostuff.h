#ifndef CRYPTOSTUFF_H
#define CRYPTOSTUFF_H

#include "daoc.h"

#include <mycrypt.h>

#include <openssl/rand.h>
#include <openssl/rsa.h>

void setup_sbox_from_key(char *key, int keylen, unsigned char *sym_sbox);

void rc4_read(unsigned char *buff, int len, unsigned char *sym_sbox);
void rc4_write(unsigned char *buff, int len, unsigned char *sym_sbox);

void prepare_rsa(unsigned char *buf, int inlen, unsigned char *output, unsigned long *outlen);

#endif // CRYPTOSTUFF_H