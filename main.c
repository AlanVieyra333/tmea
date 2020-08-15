#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "gcm.h"
#include "utils.h"

void test_gcm() {
  unsigned char K[] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                       0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
  unsigned char A[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                       0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                       0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13};
  unsigned char P[] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                       0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                       0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
  unsigned char IV[] = {34, 15,  20, 79,  33,  7, 1,  99,
                        58, 109, 12, 218, 172, 4, 86, 42};
  size_t n = 96 / 8, a = 160 / 8, Plen = 192, p = ceill(Plen / 8.0);
  size_t iv = 16;
  size_t c = p;
  __uint8_t C[c], P_decrypt[p];
  __uint8_t T[16];

  printf("K: %s\n", bytes_to_hex(K, 16));
  printf("A: %s\n", bytes_to_hex(A, a));
  printf("P: %s\n", bytes_to_hex(P, p));
  printf("IV: %s\n", bytes_to_hex(IV, iv));

  struct timeval t1_e = get_timestamp();
  gcm_encrypt(P, p, A, a, IV, iv, K, T, C);
  struct timeval t2_e = get_timestamp();

  struct timeval t1_d = get_timestamp();
  int dec_status = gcm_decrypt(C, c, A, a, IV, iv, K, T, P_decrypt);
  struct timeval t2_d = get_timestamp();

  printf("C encrypt: %s\n", bytes_to_hex(C, c));
  printf("Tag: %s\n", bytes_to_hex(T, 16));

  if (dec_status == 1) {
    printf("P decrypt: %s\n", bytes_to_hex(P_decrypt, p));
  } else {
    printf("P decrypt: INVALID\n");
  }

  printf("\nTime encrypt: %f ms.\n", (t2_e.tv_usec - t1_e.tv_usec) / 1000.0);
  printf("Time decrypt: %f ms.\n", (t2_d.tv_usec - t1_d.tv_usec) / 1000.0);
}

int main() {
  printf(">>>>> GCM\n");
  test_gcm();

  return 0;
}
