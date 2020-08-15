void AES_GCM_encrypt(const unsigned char *in, unsigned char *out,
                     const unsigned char *addt, const unsigned char *ivec,
                     unsigned char *tag, int nbytes, int abytes, int ibytes,
                     const unsigned char *key, int nr);
int AES_GCM_decrypt(const unsigned char *in, unsigned char *out,
                    const unsigned char *addt, const unsigned char *ivec,
                    unsigned char *tag, int nbytes, int abytes, int ibytes,
                    const unsigned char *key, int nr);
