#include <wmmintrin.h>

void AES_128_Key_Expansion(const unsigned char *key,
                           unsigned char *key_expanded);
void AES_128_Key_Expansion_Inv(const unsigned char *key,
                               unsigned char *key_expanded);

void AES_block_encrypt(__m128i in, __m128i *out, __m128i *key,
                       int number_of_rounds);

void AES_block_decrypt(__m128i in, __m128i *out, __m128i *key,
                       int number_of_rounds);

void AES_ECB_encrypt(const unsigned char *in, unsigned char *out,
                     unsigned long length, const char *key,
                     int number_of_rounds);
void AES_ECB_decrypt(const unsigned char *in, unsigned char *out,
                     unsigned long length, const char *key,
                     int number_of_rounds);

void AES_CBC_encrypt(const unsigned char *in, unsigned char *out,
                     unsigned char ivec[16], unsigned long length,
                     unsigned char *key, int number_of_rounds);
void AES_CBC_decrypt(const unsigned char *in, unsigned char *out,
                     unsigned char ivec[16], unsigned long length,
                     unsigned char *key, int number_of_rounds);

void AES_CTR_encrypt(const unsigned char *in, unsigned char *out,
                     const unsigned char ivec[8], const unsigned char nonce[4],
                     unsigned long length, const unsigned char *key,
                     int number_of_rounds);