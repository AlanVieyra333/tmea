#include <stddef.h>
#include <sys/time.h>

struct timeval get_timestamp();
unsigned char* hex_to_bytes(const char* hex_str);
char* bytes_to_hex(unsigned char* bytes, int len);
unsigned char* bit_padding(unsigned char* in, int len);
unsigned char* cms_padding(unsigned char* in, int len);
unsigned char* without_cms_padding(unsigned char* in, int len);
void _xor (unsigned char* a, unsigned char* b, size_t Blen, unsigned char* out);
void encode_x_in_s(size_t x, size_t s, unsigned char* out);
size_t bits_len(size_t bytes_len);
size_t bytes_len(size_t bites_len);
