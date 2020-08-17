#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "gcm.h"
#include "tmea_tree.hpp"
#include "utils.h"

void test_gcm() {
  // Block cipher key.
  unsigned char K[] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                       0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
  // Additional authenticated data.
  unsigned char A[] = {0xf5, 0x37};
  // Plain text.
  unsigned char P[] = {0x00, 0x00, 0x00, 0x00};
  // Initialization vector.
  unsigned char IV[] = {34, 15,  20, 79,  33,  7, 1,  99,
                        58, 109, 12, 218, 172, 4, 86, 42};
  size_t a = 2, p = 4, iv = 16;
  size_t c = p;
  uint8_t C[c], P_decrypt[p];
  uint8_t T[16];

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

void test_tmea() {
  uint8_t nonce[2];
  TMEA_Tree tree(nonce);

  uint8_t data[4] = {0x01, 0x02, 0x03, 0x04};
  // tree.modify_node(data, 1);

  tree.print();
}

int main() {
  srand(time(0));

  // printf(">>>>> GCM\n");
  // test_gcm();

  test_tmea();

  return 0;
}
