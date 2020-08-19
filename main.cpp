#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "tmea_tree.hpp"
#include "utils.h"

void test_tmea() {
  TMEA_Tree *tree;
  uint8_t data[TREE_SIZE] = {1, 2,  3,  4,  5,  6,  7,  8,
                             9, 10, 11, 12, 13, 14, 15, 16};
  FILE *file;

  // Crear arbol binario cifrado a partir de los datos de entrada.
  tree = new TMEA_Tree(data);
  tree->print();

  // Exportar arbol cifrado en archivo.
  file = fopen("encrypt.dat", "wb");
  tree->export_tree(file);
  fclose(file);

  // Importar un arbol cifrado de un archivo.
  file = fopen("encrypt.dat", "rb");
  tree = new TMEA_Tree(file);
  fclose(file);
  tree->print();

  // Imprimir arbol descifrado.
  if (tree->decrypt()) {
    printf("\nArbol descifrado.\n");
    tree->print();
  } else {
    printf("Error descifrando arbol. (INVALID nonce)\n");
  }
}

int main() {
  srand(time(0));

  test_tmea();

  return 0;
}
