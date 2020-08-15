#include <stddef.h>

void gcm_encrypt(unsigned char* P, size_t p, unsigned char* A, size_t a,
                 unsigned char* IV, size_t iv, unsigned char* key,
                 unsigned char* T, unsigned char* out);
int gcm_decrypt(unsigned char* C, size_t c, unsigned char* A, size_t a,
                unsigned char* IV, size_t iv, unsigned char* key,
                unsigned char* T, unsigned char* out);
void GHASH(unsigned char* X, size_t x, unsigned char* H, size_t h,
           unsigned char* out);