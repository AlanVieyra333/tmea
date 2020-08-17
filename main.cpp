#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "tmea_tree.hpp"
#include "utils.h"

void test_tmea() {
  uint8_t data[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  uint8_t nonce[2];

  TMEA_Tree tree(data, nonce);

  printf("Nonce: %s\n", bytes_to_hex(nonce, 2));
  tree.print();

  if (tree.decrypt(nonce)) {
    printf("\nArbol descifrado.\n");
    tree.print();
  } else {
    printf("Error descifrando arbol. (INVALID nonce)\n");
  }
}

int main() {
  srand(time(0));

  test_tmea();

  return 0;
}
