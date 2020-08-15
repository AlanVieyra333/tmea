#define ROUNDS 10

unsigned char* hex_to_bytes(const char* hex_str);
char* bytes_to_hex(unsigned char* bytes, int len);
unsigned char* padding(unsigned char* in, int len);
char* text_encrypt(char* text, char* key_bytes);
char* text_decrypt(char* encrypt, char* key_bytes);
