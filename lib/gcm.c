#include "gcm.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "aes-intrinsics.h"
#include "gcm-intrinsics.h"
#include "utils.h"

void gcm_encrypt(unsigned char* P, size_t p, unsigned char* A, size_t a,
                 unsigned char* IV, size_t iv, unsigned char* key,
                 unsigned char* T, unsigned char* out) {
  unsigned char key_expanded[16 * (ROUNDS + 1)];

  AES_128_Key_Expansion((const unsigned char*)key, key_expanded);
  AES_GCM_encrypt(P, out, A, IV, T, p, a, iv, key_expanded, ROUNDS);
}

int gcm_decrypt(unsigned char* C, size_t c, unsigned char* A, size_t a,
                unsigned char* IV, size_t iv, unsigned char* key,
                unsigned char* T, unsigned char* out) {
  unsigned char key_expanded[16 * (ROUNDS + 1)];

  AES_128_Key_Expansion((const unsigned char*)key, key_expanded);
  return AES_GCM_decrypt(C, out, A, IV, T, c, a, iv, key_expanded, ROUNDS);
}

void GHASH(unsigned char* X, size_t x, unsigned char* H, size_t h,
           unsigned char* out) {
  // 1. Let X 1 , X 2 , ... , X m-1 , X m denote the unique sequence of blocks
  // such that X = X 1 || X 2 ||... || X m-1 || X m .
  size_t m = ceill(x / 16.0);

  u_int8_t Y[16 * m];

  // 2.
  memset(&Y[0], 0, 16);

  // 3.
  for (size_t i = 1; i <= m; i++) {
    _xor(&Y[16 * (i - 1)], &X[16 * (i - 1)], 16 * 8, &Y[16 * i]);
    // Y[16 * i] = Y[16 * i]
  }
  // Ym[0] =

  // 2. Let Y 0 be the “zero block,” 0^128 .
  // 3. For i = 1, ..., m, let Y i = (Y i-1 ⊕ X i ) • H.
  // 4. Return Y m .
}