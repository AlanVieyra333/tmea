#include "aes-intrinsics.h"

#include <emmintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>

#include "utils.h"

static inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
  __m128i temp3;
  temp2 = _mm_shuffle_epi32(temp2, 0xff);
  temp3 = _mm_slli_si128(temp1, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp1 = _mm_xor_si128(temp1, temp2);
  return temp1;
}

void AES_128_Key_Expansion(const unsigned char *key,
                           unsigned char *key_expanded) {
  __m128i temp1, temp2;
  __m128i *Key_Schedule = (__m128i *)key_expanded;
  temp1 = _mm_loadu_si128((__m128i *)key);
  Key_Schedule[0] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[1] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[2] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[3] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[4] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[5] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[6] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[7] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[8] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[9] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[10] = temp1;
}

void AES_128_Key_Expansion_Inv(const unsigned char *key,
                               unsigned char *key_expanded) {
  unsigned char key_expanded_tmp[16 * 11];
  AES_128_Key_Expansion(key, key_expanded_tmp);

  __m128i *Key_Schedule = (__m128i *)key_expanded;
  __m128i *Key_Schedule_tmp = (__m128i *)key_expanded_tmp;

  Key_Schedule[0] = Key_Schedule_tmp[10];
  Key_Schedule[1] = _mm_aesimc_si128(Key_Schedule_tmp[9]);
  Key_Schedule[2] = _mm_aesimc_si128(Key_Schedule_tmp[8]);
  Key_Schedule[3] = _mm_aesimc_si128(Key_Schedule_tmp[7]);
  Key_Schedule[4] = _mm_aesimc_si128(Key_Schedule_tmp[6]);
  Key_Schedule[5] = _mm_aesimc_si128(Key_Schedule_tmp[5]);
  Key_Schedule[6] = _mm_aesimc_si128(Key_Schedule_tmp[4]);
  Key_Schedule[7] = _mm_aesimc_si128(Key_Schedule_tmp[3]);
  Key_Schedule[8] = _mm_aesimc_si128(Key_Schedule_tmp[2]);
  Key_Schedule[9] = _mm_aesimc_si128(Key_Schedule_tmp[1]);
  Key_Schedule[10] = Key_Schedule_tmp[0];
}

void AES_block_encrypt(__m128i in, __m128i *out, __m128i *key,
                       int number_of_rounds) {
  __m128i tmp;
  int j;

  tmp = _mm_xor_si128(in, key[0]);
  for (j = 1; j < number_of_rounds; j++) {
    tmp = _mm_aesenc_si128(tmp, ((__m128i *)key)[j]);
  }
  *out = _mm_aesenclast_si128(tmp, ((__m128i *)key)[number_of_rounds]);
}

void AES_block_decrypt(__m128i in, __m128i *out, __m128i *key,
                       int number_of_rounds) {
  __m128i tmp;
  int j;

  tmp = _mm_xor_si128(in, key[0]);
  for (j = 1; j < number_of_rounds; j++) {
    tmp = _mm_aesdec_si128(tmp, ((__m128i *)key)[j]);
  }
  *out = _mm_aesdeclast_si128(tmp, ((__m128i *)key)[number_of_rounds]);
}

/**
 * @param in Pointer to the PLAINTEXT
 * @param out Pointer to the CIPHERTEXT buffer
 * @param length Text length in bytes
 * @param key Pointer to the expanded key schedule
 * @param number_of_rounds Number of AES rounds 10,12 or 14
 *
 * @note The length of the output buffer is assumed to be a multiple of 16
 * bytes
 */
void AES_ECB_encrypt(const unsigned char *in, unsigned char *out,
                     unsigned long length, const char *key,
                     int number_of_rounds) {
  __m128i tmp;
  int i, j;

  if (length % 16)
    length = length / 16 + 1;
  else
    length = length / 16;
  for (i = 0; i < length; i++) {
    tmp = _mm_loadu_si128(&((__m128i *)in)[i]);
    tmp = _mm_xor_si128(tmp, ((__m128i *)key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      tmp = _mm_aesenc_si128(tmp, ((__m128i *)key)[j]);
    }
    tmp = _mm_aesenclast_si128(tmp, ((__m128i *)key)[j]);
    _mm_storeu_si128(&((__m128i *)out)[i], tmp);
  }
}

/**
 * @param in Pointer to the CIPHERTEXT
 * @param out Pointer to the DECRYPTED TEXT buffer
 * @param length Text length in bytes
 * @param key Pointer to the expanded key schedule
 * @param number_of_rounds Number of AES rounds 10,12 or 14
 */
void AES_ECB_decrypt(const unsigned char *in, unsigned char *out,
                     unsigned long length, const char *key,
                     int number_of_rounds) {
  __m128i tmp;
  int i, j;

  if (length % 16)
    length = length / 16 + 1;
  else
    length = length / 16;
  for (i = 0; i < length; i++) {
    tmp = _mm_loadu_si128(&((__m128i *)in)[i]);
    tmp = _mm_xor_si128(tmp, ((__m128i *)key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      tmp = _mm_aesdec_si128(tmp, ((__m128i *)key)[j]);
    }
    tmp = _mm_aesdeclast_si128(tmp, ((__m128i *)key)[j]);
    _mm_storeu_si128(&((__m128i *)out)[i], tmp);
  }
}

void AES_CBC_encrypt(const unsigned char *in, unsigned char *out,
                     unsigned char ivec[16], unsigned long length,
                     unsigned char *key, int number_of_rounds) {
  __m128i feedback, data;

  int i;

  if (length % 16)
    length = length / 16 + 1;
  else
    length /= 16;

  feedback = _mm_loadu_si128((__m128i *)ivec);
  for (i = 0; i < length; i++) {
    data = _mm_loadu_si128(&((__m128i *)in)[i]);

    feedback = _mm_xor_si128(data, feedback);

    AES_block_encrypt(feedback, &feedback, (__m128i *)key, number_of_rounds);

    _mm_storeu_si128(&((__m128i *)out)[i], feedback);
  }
}

void AES_CBC_decrypt(const unsigned char *in, unsigned char *out,
                     unsigned char ivec[16], unsigned long length,
                     unsigned char *key, int number_of_rounds) {
  __m128i data, feedback, last_in;
  int i;
  if (length % 16)
    length = length / 16 + 1;
  else
    length /= 16;
  feedback = _mm_loadu_si128((__m128i *)ivec);
  for (i = 0; i < length; i++) {
    last_in = _mm_loadu_si128(&((__m128i *)in)[i]);

    AES_block_decrypt(last_in, &data, (__m128i *)key, number_of_rounds);

    data = _mm_xor_si128(data, feedback);

    _mm_storeu_si128(&((__m128i *)out)[i], data);
    feedback = last_in;
  }
}

void AES_CTR_encrypt(const unsigned char *in, unsigned char *out,
                     const unsigned char ivec[8], const unsigned char nonce[4],
                     unsigned long length, const unsigned char *key,
                     int number_of_rounds) {
  __m128i ctr_block, tmp, ONE, BSWAP_EPI64;
  int i, j;
  if (length % 16)
    length = length / 16 + 1;
  else
    length /= 16;
  ONE = _mm_set_epi32(0, 1, 0, 0);
  BSWAP_EPI64 =
      _mm_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
  ctr_block = _mm_insert_epi64(ctr_block, *(long long *)ivec, 1);
  ctr_block = _mm_insert_epi32(ctr_block, *(long *)nonce, 1);
  ctr_block = _mm_srli_si128(ctr_block, 4);
  ctr_block = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
  ctr_block = _mm_add_epi64(ctr_block, ONE);
  for (i = 0; i < length; i++) {
    tmp = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp = _mm_xor_si128(tmp, ((__m128i *)key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      tmp = _mm_aesenc_si128(tmp, ((__m128i *)key)[j]);
    };
    tmp = _mm_aesenclast_si128(tmp, ((__m128i *)key)[j]);
    tmp = _mm_xor_si128(tmp, _mm_loadu_si128(&((__m128i *)in)[i]));
    _mm_storeu_si128(&((__m128i *)out)[i], tmp);
  }
}