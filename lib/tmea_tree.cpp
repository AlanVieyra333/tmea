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
size_t iv = 16;

void gen_nonce(uint8_t nonce[NONCE_SIZE]);
Node *create_node();
bool is_leaf(Node *node);
void encrypt_node(Node *node, uint8_t A[NONCE_SIZE]);
int decrypt_node(Node *node, uint8_t A[NONCE_SIZE]);
void update_node(Node *node, uint8_t data[DATA_SIZE], uint8_t nonce[NONCE_SIZE],
                 int position, int l, int r);
void print_node(Node *node, int spaces);
Node *import_node(FILE *file, int levels);
void export_node(Node *node, FILE *file);
void save_node(Node *node, FILE *file);

TMEA_Tree::TMEA_Tree() { this->tree = create_tree(LEVELS, this->nonce); }

/**
 * Crea un arbol binario cifrado con los datos recibidos.
 */
TMEA_Tree::TMEA_Tree(uint8_t data[TREE_SIZE]) {
  this->tree = create_tree(LEVELS, this->nonce);

  update_leaf(1, data, this->nonce);
  update_leaf(2, &data[DATA_SIZE], this->nonce);
  update_leaf(3, &data[DATA_SIZE * 2], this->nonce);
  update_leaf(4, &data[DATA_SIZE * 3], this->nonce);
}

/**
 * Carga un arbol cifrado en un archivo binario.
 */
TMEA_Tree::TMEA_Tree(FILE *file) {
  fread(this->nonce, 1, NONCE_SIZE, file);

  this->tree = import_node(file, LEVELS);
}

TMEA_Tree::~TMEA_Tree() {}

/**
 * Crea un arbol binario de 'levels' niveles con sus datos en 0's cifrado
 * con el algoritmo gcm.
 * Actualiza el valor de nonce con el cual se puede descifrar.
 */
Node *TMEA_Tree::create_tree(int levels, uint8_t nonce[NONCE_SIZE]) {
  if (levels < 1) {
    return NULL;
  }

  Node *node = create_node();
  uint8_t *nonce_left = (node->element)->data.nonce.left;
  uint8_t *nonce_right = (node->element)->data.nonce.right;

  node->left = create_tree(levels - 1, nonce_left);
  node->right = create_tree(levels - 1, nonce_right);

  encrypt_node(node, nonce);

  return node;
}

void TMEA_Tree::update_leaf(int pos_leaf, uint8_t data[DATA_SIZE],
                            uint8_t nonce[NONCE_SIZE]) {
  update_node(this->tree, data, nonce, pos_leaf, 1, (int)pow(2.0, LEVELS - 1));
}

int TMEA_Tree::decrypt_tree(Node *node, uint8_t nonce[NONCE_SIZE]) {
  uint8_t nonce_left[NONCE_SIZE], nonce_right[NONCE_SIZE];
  int dec_status;

  if (node == NULL) {
    return 1;
  }

  if (!decrypt_node(node, nonce)) return 0;

  memcpy(nonce_left, node->element->data.nonce.left, NONCE_SIZE);
  memcpy(nonce_right, node->element->data.nonce.right, NONCE_SIZE);

  if (!decrypt_tree(node->left, nonce_left)) return 0;
  if (!decrypt_tree(node->right, nonce_right)) return 0;

  return 1;
}

int TMEA_Tree::decrypt() { return decrypt_tree(this->tree, this->nonce); }

/**
 * Imprime el arbol.
 */
void TMEA_Tree::print() {
  printf("Tree:\n");
  printf("  Nonce: %s\n", bytes_to_hex(this->nonce, NONCE_SIZE));
  print_node(this->tree, 0);
}

/**
 * Guarda el arbol cifrado en un archivo binario.
 */
void TMEA_Tree::export_tree(FILE *file) {
  fwrite(this->nonce, 1, NONCE_SIZE, file);

  export_node(this->tree, file);
}

/**
 * Guarda los datos de las hojas del arbol en un archivo binario.
 */
void TMEA_Tree::save_data(FILE *file) { save_node(this->tree, file); }

// ###################################################################

/**
 * Nonce generado aleatoriamente de tamano 2 bytes.
 */
void gen_nonce(uint8_t nonce[NONCE_SIZE]) {
  for (size_t i = 0; i < NONCE_SIZE; i++) {
    nonce[i] = (uint8_t)rand() + 1;
  }
}

/**
 * Crea un nodo con sus valores vacios.
 */
Node *create_node() {
  Node *node = new Node;
  node->element = new TMEA_Element();
  node->left = NULL;
  node->right = NULL;

  return node;
}

bool is_leaf(Node *node) { return node->left == NULL && node->right == NULL; }

/**
 * Cifra los datos (4 bytes) de un nodo y genera un nonce de 2 bytes en A.
 */
void encrypt_node(Node *node, uint8_t A[NONCE_SIZE]) {
  TMEA_Element *element = node->element;
  uint8_t *T = element->tag;
  uint8_t *C = element->data.data;
  size_t p = NONCE_SIZE * 2;

  if (is_leaf(node)) {
    p = DATA_SIZE;
  }

  // Plain text.
  unsigned char P[p];
  memcpy(P, &element->data.data, p);

  // Additional authenticated data.
  gen_nonce(A);

  gcm_encrypt(P, p, A, NONCE_SIZE, IV, iv, K, T, C);
}

/**
 * Descifra los datos (4 bytes) de un nodo con su nonce asociado.
 */
int decrypt_node(Node *node, uint8_t A[NONCE_SIZE]) {
  TMEA_Element *element = node->element;
  uint8_t *T = element->tag;
  uint8_t *P = element->data.data;
  size_t c = NONCE_SIZE * 2;

  if (is_leaf(node)) {
    c = DATA_SIZE;
  }

  // Encrypt text.
  uint8_t C[c];
  memcpy(C, &element->data.data, c);

  return gcm_decrypt(C, c, A, NONCE_SIZE, IV, iv, K, T, P);
}

/**
 * Modifica los datos de un nodo y vuelve a cifrar recursivamente hacia
 * el nodo raiz.
 */
void update_node(Node *node, uint8_t data[DATA_SIZE], uint8_t nonce[NONCE_SIZE],
                 int position, int l, int r) {
  int mid;
  uint8_t *nonce_left, *nonce_right;

  // Base case.
  if (node == NULL) return;

  if (decrypt_node(node, nonce) != 1) {
    printf("INVALID nonce\n");
    return;
  }

  nonce_left = (node->element)->data.nonce.left;
  nonce_right = (node->element)->data.nonce.right;

  mid = l + (r - l) / 2;
  if (position <= mid) {
    update_node(node->left, data, nonce_left, position, l, mid - 1);
  } else {
    update_node(node->right, data, nonce_right, position, mid + 1, r);
  }

  // Copy data to node and encript.
  if (is_leaf(node)) {
    memcpy(node->element->data.data, data, DATA_SIZE);
  }

  encrypt_node(node, nonce);
}

/**
 * Imprime los nodos recursivamente.
 */
void print_node(Node *node, int spaces) {
  // Base case
  if (node == NULL) return;

  int buff_size = NONCE_SIZE * 2;

  if (is_leaf(node)) {
    buff_size = DATA_SIZE;
  }

  // Increase distance between levels
  spaces++;

  // Process right child first
  print_node(node->right, spaces);

  // Print current node after space count
  printf("\n");
  for (int i = 1; i < spaces; i++) printf("\t\t");
  printf("(%s | %s)\n", bytes_to_hex(node->element->data.data, buff_size),
         bytes_to_hex(node->element->tag, 16));
  // printf("([%llu, %llu][%s])\n", node->element->data.nonce.left,
  //        node->element->data.nonce.right, node->element->tag);

  // Process left child
  print_node(node->left, spaces);
}

/**
 * Carga los nodos cifrados de manera recursiva (recorrido preorden) de un
 * archivo binario.
 */
Node *import_node(FILE *file, int levels) {
  if (levels < 1) {
    return NULL;
  }

  int buff_size = NONCE_SIZE * 2;
  Node *node = create_node();

  if (levels == 1) {
    buff_size = DATA_SIZE;
  }

  uint8_t buff[buff_size];

  fread(node->element->data.data, 1, buff_size, file);
  fread(node->element->tag, 1, 16, file);

  node->left = import_node(file, levels - 1);
  node->right = import_node(file, levels - 1);

  return node;
}

/**
 * Guarda los nodos cifrados de manera recursiva (recorrido preorden) en un
 * archivo binario.
 */
void export_node(Node *node, FILE *file) {
  // Base case.
  if (node == NULL) {
    return;
  }

  int buf_size = NONCE_SIZE * 2;

  if (is_leaf(node)) {
    buf_size = DATA_SIZE;
  }

  fwrite(node->element->data.data, 1, buf_size, file);
  fwrite(node->element->tag, 1, 16, file);

  export_node(node->left, file);
  export_node(node->right, file);
}

/**
 * Guarda los datos si el nodo es hoja en un archivo binario.
 */
void save_node(Node *node, FILE *file) {
  if (node == NULL) {
    return;
  } else if (is_leaf(node)) {
    fwrite(node->element->data.data, 1, DATA_SIZE, file);
  }

  save_node(node->left, file);
  save_node(node->right, file);
}
