#include <stdint.h>
#include <stdlib.h>

#define LEVELS 3

typedef struct _Nonce {
  uint16_t left;
  uint16_t right;
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
  Node *create_tree(int levels);
  void encrypt_node(Node &node, uint8_t A[2]);
  void print(Node *node, int spaces);

 public:
  TMEA_Tree();
  ~TMEA_Tree();
  void print();
};
