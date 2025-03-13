#pragma once

#include <stdint.h>

#define INIT   0
#define NORMAL 1

typedef struct
{
	unsigned int  A[5];
	unsigned int  B[11];
	unsigned int  L1, R1, L2, R2;

} kcipher2_state;

extern unsigned int   IK[12];
extern unsigned int   IV[4];
extern kcipher2_state State;

void kcipher2_encrypt(unsigned char* in, unsigned long len, unsigned char* out);
void kcipher2_init(unsigned int* key, unsigned int* iv);

typedef struct {
    kcipher2_state state;
    uint64_t remaining;
    char buffer[2000*64];
} kcipher2_stream;

void init_kcipher2_stream(kcipher2_stream *stream, kcipher2_state *state);

void kcipher2_xor_data(
    kcipher2_stream *stream,
    uint64_t size,
   	uint8_t *data);    
