
typedef struct _Node {
  struct _Node *left, *right;
  void* element;
} Node;

typedef struct _TMEA_node {
  char *nonce_left, *nonce_right;
  char* tag;
} TMEA_node;

typedef struct _TMEA_leaf {
  char* data;
  char* tag;
} TMEA_leaf;
