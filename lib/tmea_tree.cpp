#include "tmea_tree.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gcm.h"
#include "utils.h"

// Block cipher key.
unsigned char K[] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                     0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
// Initialization vector.
unsigned char IV[] = {34, 15,  20, 79,  33,  7, 1,  99,
                      58, 109, 12, 218, 172, 4, 86, 42};
size_t iv = 16, p = 4, a = 2, c = p;

/**
 * Nonce generado aleatoriamente de tamano 2 bytes.
 */
uint16_t gen_nonce() { return (rand() % (65535 + 1)); }

TMEA_Tree::TMEA_Tree() { this->tree = create_tree(LEVELS); }

TMEA_Tree::~TMEA_Tree() {}

/**
 * Crea un nodo con sus valores vacios.
 * 
 */
Node* TMEA_Tree::create_node() {
  TMEA_Element* element = new TMEA_Element();
  memset(element, 0, sizeof(TMEA_Element));

  Node* node = new Node;
  node->element = (void*)element;
  node->left = NULL;
  node->right = NULL;

  return node;
}

Node* TMEA_Tree::create_tree(int levels) {
  Node* tree = create_node();

  if (levels > 1) {
    tree->left = create_tree(levels - 1);
    tree->right = create_tree(levels - 1);
  }

  return tree;
}

/**
 * Cifra los datos (4 bytes) de un nodo y genera un nonce de 2 bytes en A.
 */
void TMEA_Tree::encrypt_node(Node& node, uint8_t A[2]) {
  TMEA_Element* element = (TMEA_Element*)node.element;
  uint8_t* T = element->tag;
  uint8_t* C = element->data.data;

  // Plain text.
  unsigned char P[p];
  memcpy(P, &element->data.data, p);

  // Additional authenticated data.
  uint16_t nonce = gen_nonce();
  memcpy(A, &nonce, a);

  gcm_encrypt(P, p, A, a, IV, iv, K, T, C);
}

/**
 * Imprime el arbol.
 */
void TMEA_Tree::print() { print(this->tree, 0); }

/**
 * Imprime los nodos recursivamente.
 */
void TMEA_Tree::print(Node* node, int spaces) {
  // Base case
  if (node == NULL) return;

  // Increase distance between levels
  spaces++;

  // Process right child first
  print(node->right, spaces);

  // Print current node after space count
  printf("\n");
  for (int i = 1; i < spaces; i++) printf("\t   ");
  TMEA_Element element = *((TMEA_Element*)node->element);
  printf("([%s][%s])\n", element.data.data, element.tag);
  // printf("([%llu, %llu][%s])\n", element.data.nonce.left,
  //        element.data.nonce.right, element.tag);

  // Process left child
  print(node->left, spaces);
}