#include "aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes-intrinsics.h"
#include "utils.h"

#define IV \
  { 34, 15, 20, 79, 33, 7, 1, 99, 58, 109, 12, 218, 172, 4, 86, 42 }

char* text_encrypt(char* text, char* key_bytes) {
  int len = strlen(text);
  unsigned char* text_bytes = cms_padding((unsigned char*)text, len);
  int newLen =
      ((len + 1) % 16 == 0) ? (len + 1) : (len + 1) + (16 - (len + 1) % 16);

  unsigned char key_expanded[16 * (ROUNDS + 1)];
  unsigned char encrypt_bytes[newLen];
  unsigned char ivec[16] = IV;

  AES_128_Key_Expansion((const unsigned char*)key_bytes, key_expanded);
  AES_CBC_encrypt(text_bytes, encrypt_bytes, ivec, newLen, key_expanded,
                  ROUNDS);

  char* encrypt = bytes_to_hex(encrypt_bytes, newLen);

  free(text_bytes);

  return encrypt;
}

char* text_decrypt(char* encrypt, char* key_bytes) {
  int len = strlen(encrypt);
  unsigned char* encrypt_bytes = hex_to_bytes(encrypt);
  unsigned char* decrypt_with_padding = (unsigned char*)malloc(sizeof(char) * len / 2);

  unsigned char key_expanded[16 * (ROUNDS + 1)];
  unsigned char ivec[16] = IV;

  AES_128_Key_Expansion_Inv((const unsigned char*)key_bytes, key_expanded);
  AES_CBC_decrypt(encrypt_bytes, decrypt_with_padding, ivec, len / 2,
                  key_expanded, ROUNDS);

  char* decrypt = (char*) without_cms_padding(decrypt_with_padding, len / 2);

  free(encrypt_bytes);
  free(decrypt_with_padding);

  return decrypt;
}
