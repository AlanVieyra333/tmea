#include <stdint.h>
#include <stdlib.h>

#define LEVELS 3

typedef struct _Nonce {
  uint8_t left[2];
  uint8_t right[2];
} Nonce;

union Data {
  Nonce nonce;
  uint8_t data[4];
};

typedef struct _TMEA_Element {
  Data data;
  uint8_t tag[16];
} TMEA_Element;

typedef struct _Node {
  struct _Node *left, *right;
  void *element;
} Node;

class TMEA_Tree {
 private:
  Node *tree;
  Node *create_node();
  Node *create_tree(int levels, uint8_t nonce[2]);
  void encrypt_node(Node *node, uint8_t A[2]);
  void print(Node *node, int spaces);

 public:
  TMEA_Tree(uint8_t nonce[2]);
  ~TMEA_Tree();
  void modify_node(uint8_t data[4], int pos_leaf);
  void print();
};
