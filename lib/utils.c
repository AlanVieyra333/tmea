#include "utils.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct timeval get_timestamp() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv;
}

unsigned char* hex_to_bytes(const char* hex_str) {
  int len = strlen(hex_str);
  unsigned char* bytes =
      (unsigned char*)malloc(sizeof(unsigned char) * (len / 2 + 1));

  for (int i = 0; i < len / 2; i++) {
    sscanf(&hex_str[2 * i], "%02x", (unsigned int*)&bytes[i]);
  }

  bytes[len / 2 + 1] = 0;

  return bytes;
}

char* bytes_to_hex(unsigned char* bytes, int len) {
  char* hex = (char*)malloc(sizeof(char) * (2 * len + 1));

  for (int i = 0; i < len; i++) {
    sprintf(&hex[2 * i], "%02x", bytes[i]);
  }

  hex[2 * len + 1] = 0;

  return hex;
}

unsigned char* bit_padding(unsigned char* in, int len) {
  int restante = 16 - ((len + 1) % 16);
  int newLen = (len + 1) + restante;

  unsigned char* result =
      (unsigned char*)malloc(sizeof(unsigned char) * newLen);

  memset(result, 0, sizeof(char) * newLen);
  memcpy(result, in, len);

  result[len] = 0x80;

  return result;
}

unsigned char* cms_padding(unsigned char* in, int len) {
  int restante = 16 - (len % 16);
  restante = restante == 0 ? 16 : restante;
  int newLen = (len + restante);

  unsigned char* result =
      (unsigned char*)malloc(sizeof(unsigned char) * newLen);

  memset(result, 0, sizeof(char) * newLen);
  memcpy(result, in, len);

  for (int i = 0; i < restante; i++) {
    result[len + i] = restante;
  }

  return result;
}

unsigned char* without_cms_padding(unsigned char* in, int len) {
  int padding = in[len - 1];
  int newLen = len - padding;

  unsigned char* result =
      (unsigned char*)malloc(sizeof(unsigned char) * (newLen + 1));

  memcpy(result, in, newLen);
  result[newLen] = 0;

  return result;
}

/**
 * @param Blen Bits to opply xor binary operation.
 */
void xor
    (unsigned char* a, unsigned char* b, size_t Blen, unsigned char* out) {
      __uint8_t residue = Blen % 8;
      size_t len = residue == 0 ? Blen / 8 : (Blen / 8) + 1;

      for (size_t i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
      }

      if (residue > 0) {
        __uint8_t aux_residue_and_op = (1 << residue) - 1;
        aux_residue_and_op <<= 8 - aux_residue_and_op;

        out[len - 1] = (a[len - 1] ^ b[len - 1]) & aux_residue_and_op;
      }
    }

    /**
     * Encode a number x in s bits.
     */
    void encode_x_in_s(size_t x, size_t s, unsigned char* out) {
  __uint8_t s_residue = s % 8;
  size_t encode_len = ceill(s / 8.0); /* Number of bytes */
  memset(out, 0, encode_len);

  /* Copy bytes of x number into a bytes array */
  __uint8_t x_bytes_len = encode_len > 8 ? 8 : encode_len;
  __uint8_t x_bytes[x_bytes_len];
  memcpy(x_bytes, &x, x_bytes_len);

  /* Remove excess bits */
  if (s_residue != 0) {
    __uint8_t aux_residue_and_op = (1 << s_residue) - 1;
    x_bytes[x_bytes_len - 1] &= aux_residue_and_op;
  }

  /* Copy in reverse bytes array of x number */
  for (__uint8_t i = 0; i < x_bytes_len; i++) {
    out[encode_len - 1 - i] = x_bytes[i];
  }
}

size_t bits_len(size_t bytes_len) { return bytes_len * 8; }

size_t bytes_len(size_t bits_len) { return ceill(bits_len / 8.0); }

/**
 * @param a Byte array of 16 bytes.
 * @param b Byte array of 16 bytes.
 * @param out Byte array of 32 bytes.
 */
void mult(unsigned char* a, unsigned char* b, unsigned char* out) {
  // __m128i res_ll, res_hl, res_lh, res_hh_aux;
  // __m256i res_hh, result;
  // __m128i __a = _mm_loadu_si128((__m128i*)a);
  // __m128i __b = _mm_loadu_si128((__m128i*)b);

  // res_ll = _mm_clmulepi64_si128(__a, __b, 0x00);
  // res_hl = _mm_clmulepi64_si128(__a, __b, 0x01);
  // res_lh = _mm_clmulepi64_si128(__a, __b, 0x10);
  // res_hh_aux = _mm_clmulepi64_si128(__a, __b, 0x11);

  // /* Offset */
  // res_hl = res_hl << 64;
  // res_lh = res_lh << 64;

  // uint8_t res_hh_aux_array[32];
  // memset(res_hh_aux_array, 0, 32);
  // _mm_storeu_si128((__m128i*)res_hh_aux_array, res_hh_aux);
  // res_hh = _mm256_loadu_si256((__m256i*)res_hh_aux_array);
  // res_hh = res_hh << 128;

  // /* Reduction */

  // _mm_storeu_si128((__m128i*)out, result);
}