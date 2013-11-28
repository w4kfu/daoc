#include "cryptostuff.h"

unsigned char daoc_pub[] = 
{
	0x91, 0x00, 0x00, 0x00, 0x01, 0xC1, 0x00, 0x00, 0x00, 0x02, 0x15, 0xB3,
	0x4E, 0xAF, 0x3A, 0x93, 0xA3, 0xC7, 0x4A, 0x6A, 0xFD, 0x69, 0x55, 0x45,
	0x1D, 0x38, 0x6A, 0x8D, 0xA1, 0xDF, 0x70, 0x1F, 0x84, 0x93, 0x23, 0xE7,
	0x95, 0x7F, 0xFD, 0xC5, 0x78, 0xCD, 0x42, 0x58, 0x71, 0x6B, 0xA4, 0xB5,
	0x4D, 0xDD, 0xF1, 0xC6, 0xB9, 0xAE, 0xF2, 0x41, 0x65, 0xF7, 0xD9, 0x4D,
	0x9C, 0xC5, 0xD6, 0xEE, 0x0D, 0x98, 0xFC, 0x23, 0x7E, 0x94, 0x84, 0xE2,
	0xD1, 0x27, 0x8C, 0x67, 0xFC, 0xB6, 0x2C, 0x5D, 0xD6, 0x60, 0xA6, 0xA9,
	0xC3, 0xA5, 0x04, 0x11, 0xFF, 0xFE, 0x9B, 0x90, 0x27, 0x69, 0x6A, 0x60,
	0x1D, 0x89, 0x6F, 0xFD, 0x55, 0x96, 0x4A, 0xEA, 0x97, 0x34, 0x8F, 0x69,
	0x79, 0xBF, 0x93, 0x26, 0x18, 0xB4, 0x7C, 0x7C, 0xD5, 0xAD, 0x0B, 0xC9,
	0xC5, 0xB7, 0x8F, 0x06, 0xB4, 0x37, 0x67, 0x94, 0xE0, 0x2A, 0x7E, 0x38,
	0x2F, 0x28, 0x60, 0x8A, 0xDC, 0x89, 0x7D, 0x08, 0xDD, 0xBE, 0x38, 0x34,
	0xF5, 0x78, 0xD8, 0x81, 0x58, 0x9C, 0x2B, 0x03, 0x1A, 0xE0, 0xE3, 0xF3,
	0x19, 0xE3, 0x63, 0x81, 0xE3, 0x7C, 0xE0, 0x5D, 0xBC, 0x8E, 0x9C, 0xDC,
	0x93, 0x74, 0x24, 0xE0, 0xF4, 0x96, 0x65, 0xFA, 0x90, 0x21, 0x06, 0x03,
	0xD2, 0x5A, 0xC3, 0x51, 0xBF, 0x5D, 0x03, 0xB2, 0xCD, 0xD3, 0xF1, 0x6E,
	0xCB, 0xB0, 0x25, 0x71, 0x4B, 0xC6, 0x00, 0x44, 0x7A, 0xE7, 0x03, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x01
};

unsigned char daoc_priv[209] = {
	0x91, 0x00, 0x00, 0x00, 0x01, 0xC1, 0x00, 0x00, 0x00, 0x02, 0x57, 0x9F,
	0xF9, 0x03, 0x18, 0xDA, 0xF6, 0x24, 0x1F, 0xF0, 0x17, 0xE1, 0x47, 0x37,
	0x9F, 0xD4, 0xE2, 0x1F, 0xA1, 0x68, 0x85, 0x44, 0xC9, 0x82, 0x90, 0xC1,
	0xF1, 0x91, 0xE2, 0x38, 0x58, 0x12, 0x04, 0xAD, 0x3A, 0xA7, 0xEC, 0xFA,
	0xEF, 0x81, 0x1C, 0x4F, 0xE3, 0xA7, 0xF0, 0xBE, 0x40, 0x5B, 0x89, 0x78,
	0x1B, 0x1D, 0x67, 0x9F, 0x3B, 0x7E, 0xEB, 0xCD, 0xEF, 0x76, 0xDD, 0xF0,
	0xED, 0x90, 0x5A, 0xC7, 0xC8, 0x58, 0xCC, 0x6A, 0xB6, 0x73, 0x86, 0x47,
	0x49, 0xE2, 0x63, 0x82, 0xFB, 0x20, 0xA2, 0x23, 0xC6, 0xF0, 0x8C, 0x3B,
	0x15, 0x7B, 0xA8, 0xFA, 0xB1, 0x76, 0x49, 0xCB, 0x9A, 0x36, 0xDF, 0xD7,
	0x02, 0x1A, 0x6F, 0xE0, 0xA8, 0xB1, 0x65, 0xE2, 0xEA, 0x5D, 0xBE, 0xF6,
	0xF2, 0xC7, 0x25, 0x4B, 0x58, 0xF3, 0x9A, 0x2B, 0x1B, 0xA0, 0x19, 0x65,
	0xB2, 0xD6, 0x03, 0x64, 0x9E, 0x02, 0xD7, 0xA8, 0x78, 0x33, 0x93, 0x82,
	0x91, 0x7A, 0x66, 0xE1, 0xA8, 0x3C, 0xF8, 0x14, 0x61, 0xBE, 0x05, 0xFB,
	0x45, 0xE9, 0xD9, 0xA1, 0x4D, 0x81, 0x54, 0x07, 0x58, 0xEF, 0xDC, 0xE0,
	0x64, 0x97, 0x24, 0x35, 0xDC, 0xA4, 0x06, 0xB9, 0x26, 0x3C, 0x73, 0x70,
	0xA5, 0x82, 0x27, 0x99, 0xC9, 0x6F, 0xCC, 0x85, 0x57, 0xE3, 0xC3, 0xA8,
	0xBC, 0x7A, 0x67, 0x94, 0x38, 0xEC, 0x2E, 0x0B, 0x3F, 0x71, 0x03, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x01
};


void setup_sbox_from_key(char *key, int keylen, unsigned char *sym_sbox)
{
    int x, y;
    int tmp;

    for (x = 0; x < 256; x++)
	{
        sym_sbox[x] = x;
	}

    for (x = y = 0; x < 256; x++)  
	{
        y = (y + sym_sbox[x] + key[x % keylen]) & 255;
        tmp = sym_sbox[x];
        sym_sbox[x] = sym_sbox[y];
        sym_sbox[y] = tmp;
    }
}

void rc4_read(unsigned char *buff, int len, unsigned char *sym_sbox)
{
    int x, y;
    unsigned char *s, tmp, tmp_sym_sbox[SYMKEY_SIZE];;
    int midpoint, pos;

    memcpy(tmp_sym_sbox, sym_sbox, SYMKEY_SIZE);

    x = 0;
    y = 0;
    s = tmp_sym_sbox;
    midpoint = len / 2;

    for (pos = midpoint; pos < len; pos++)
	{
        x = (x + 1) & 255;
        y = (y + s[x]) & 255;
        tmp = s[x]; s[x] = s[y]; s[y] = tmp;
        tmp = (s[x] + s[y]) & 255;
	    buff[pos] ^= s[tmp];
        y = (y + buff[pos]) & 255;
    }
    for (pos = 0; pos < midpoint; pos++) 
	{
        x = (x + 1) & 255;
        y = (y + s[x]) & 255;
        tmp = s[x]; s[x] = s[y]; s[y] = tmp;
        tmp = (s[x] + s[y]) & 255;
	    buff[pos] ^= s[tmp];
        y = (y + buff[pos]) & 255;
    }
}

void rc4_write(unsigned char *buff, int len, unsigned char *sym_sbox)
{
    int x, y;
    unsigned char *s, tmp, tmp_sym_sbox[SYMKEY_SIZE];
    int midpoint, pos;

    memcpy(tmp_sym_sbox, sym_sbox, 256);

    x = 0;
    y = 0;
    s = tmp_sym_sbox;
    midpoint = len / 2;

    for (pos = midpoint; pos < len; pos++) 
	{
        x = (x + 1) & 255;
        y = (y + s[x]) & 255;
        tmp = s[x]; s[x] = s[y]; s[y] = tmp;
        tmp = (s[x] + s[y]) & 255;
        y = (y + buff[pos]) & 255;
		buff[pos] ^= s[tmp];
    }
    for (pos = 0; pos < midpoint; pos++) 
	{
        x = (x + 1) & 255;
        y = (y + s[x]) & 255;
        tmp = s[x]; 
		s[x] = s[y]; 
		s[y] = tmp;
        tmp = (s[x] + s[y]) & 255;
        y = (y + buff[pos]) & 255;
        buff[pos] ^= s[tmp];
    }
}

void prepare_rsa(unsigned char *buf, int inlen, unsigned char *output, unsigned long *outlen)
{
	rsa_key key;
	int prng_idx;
	prng_state statesprng;
	int res;
	unsigned char rsa_in[196];
	unsigned long y, rsa_size;

	char bufprint[4096];
	
	if (rsa_import(daoc_pub, sizeof (daoc_pub), &key) != CRYPT_OK)
	{
		printf("[-] rsa_import() failed\n");
		exit(EXIT_FAILURE);
	}

	/* 
		DEBUG 
	mp_toradix(&key.e, bufprint, 10);
	printf("E = %s\n", bufprint);
	mp_toradix(&key.N, bufprint, 10);
	printf("N = %s\n", bufprint);

	*/

	register_prng(&sprng_desc);
	prng_idx = find_prng("sprng");
	if (prng_idx == -1) 
	{
		fprintf(stderr, "rsa_test requires LTC_SHA1 and yarrow\n");
		exit(EXIT_FAILURE);
	}
	y = 193;
	res = rsa_pad(buf, inlen, rsa_in, &y, prng_idx, &statesprng);
	if (res != CRYPT_OK)
	{
		fprintf(stderr, "[-] rsa_pad() failed : %d\n", res);
		exit(EXIT_FAILURE);
	}
	rsa_size = *outlen - 2;
	res = rsa_exptmod(rsa_in, y, output + 2, &rsa_size, PK_PUBLIC, &key);
	if (res != CRYPT_OK)
	{
		fprintf(stderr, "[-] rsa_exptmod() failed : %d\n", res);
		exit(EXIT_FAILURE);
	}
	*output = 0;
	*(output + 1) = rsa_size;
	*outlen = rsa_size + 2;
}