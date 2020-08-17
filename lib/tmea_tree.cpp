#include "tmea_tree.hpp"

#include <math.h>
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

TMEA_Tree::TMEA_Tree(uint8_t nonce[2]) {
  this->tree = create_tree(LEVELS, nonce);
}

TMEA_Tree::~TMEA_Tree() {}

/**
 * Crea un nodo con sus valores vacios.
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

/**
 * Crea un arbol binario de 'levels' niveles con sus datos en 0's cifrado
 * con el algoritmo gcm.
 * Actualiza el valor de nonce con el cual se puede descifrar.
 */
Node* TMEA_Tree::create_tree(int levels, uint8_t nonce[2]) {
  Node* node = create_node();
  uint8_t* nonce_left = ((TMEA_Element*)node->element)->data.nonce.left;
  uint8_t* nonce_right = ((TMEA_Element*)node->element)->data.nonce.right;

  if (levels > 1) {
    node->left = create_tree(levels - 1, nonce_left);
    node->right = create_tree(levels - 1, nonce_right);
  }

  encrypt_node(node, nonce);

  return node;
}

/**
 * Cifra los datos (4 bytes) de un nodo y genera un nonce de 2 bytes en A.
 */
void TMEA_Tree::encrypt_node(Node* node, uint8_t A[2]) {
  TMEA_Element* element = (TMEA_Element*)node->element;
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
 * Modifica los datos de un nodo y vuelve a cifrar recursivamente hacia
 * el nodo raiz.
 */
void TMEA_Tree::modify_node(uint8_t data[4], int pos_leaf) {
  Node* node = this->tree;
  int leaves = pow(2.0, LEVELS - 1);
  int l = 1, r = leaves, mid;

  // Get node in position 'pos_leaf'.
  for (size_t i = 1; i < LEVELS; i++) {
    mid = l + (r - l) / 2;
    if (pos_leaf <= mid) {
      node = node->left;

      r = mid - 1;
    } else {
      node = node->right;

      l = mid + 1;
    }
  }

  // Copy data to node.
  TMEA_Element* element = (TMEA_Element*)node->element;
  memcpy(element->data.data, data, 4);

  uint8_t nonce[2];
  encrypt_node(node, nonce);
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
  for (int i = 1; i < spaces; i++) printf("\t\t");
  TMEA_Element element = *((TMEA_Element*)node->element);
  printf("(%s | %s)\n", bytes_to_hex(element.data.data, 4),
         bytes_to_hex(element.tag, 16));
  // printf("([%llu, %llu][%s])\n", element.data.nonce.left,
  //        element.data.nonce.right, element.tag);

  // Process left child
  print(node->left, spaces);
}