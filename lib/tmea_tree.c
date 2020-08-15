#include "tmea_tree.h"

#include <stdlib.h>

/**
 * Nonce generado con el timestamp y la division de memoria.
 */
char* gen_nonce() {
  // TODO
  return "";
}

void tmea_init_tree(Node* tree) {
  TMEA_node* node = (TMEA_node*)malloc(sizeof(TMEA_node));
  node->nonce_left = gen_nonce();
  node->nonce_right = gen_nonce();
  node->tag = "";

  tree->element = (void*)node;
}