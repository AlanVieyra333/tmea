#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define LEVELS 3
#define LEAVES 4      // 2^(LEVELS-1)
#define DATA_SIZE 32   // In bytes
#define NONCE_SIZE 8  // In bytes
#define TREE_SIZE LEAVES *DATA_SIZE

typedef struct _Nonce {
  uint8_t left[NONCE_SIZE];
  uint8_t right[NONCE_SIZE];
} Nonce;

union Data {
  Nonce nonce;
  uint8_t data[DATA_SIZE];
};

typedef struct _TMEA_Element {
  Data data;
  uint8_t tag[16];
} TMEA_Element;

typedef struct _Node {
  struct _Node *left, *right;
  TMEA_Element *element;
} Node;

class TMEA_Tree {
 private:
  Node *tree;
  uint8_t nonce[NONCE_SIZE];
  Node *create_tree(int levels, uint8_t nonce[NONCE_SIZE]);
  int decrypt_tree(Node *node, uint8_t nonce[NONCE_SIZE]);
  void print(Node *node, int spaces);

 public:
  TMEA_Tree();
  TMEA_Tree(uint8_t data[TREE_SIZE]);
  TMEA_Tree(FILE *file);
  ~TMEA_Tree();
  void update_leaf(int pos_leaf, uint8_t data[DATA_SIZE],
                   uint8_t nonce[NONCE_SIZE]);
  int decrypt();
  void print();
  void export_tree(FILE *file);
  void save_data(FILE *file);
};
