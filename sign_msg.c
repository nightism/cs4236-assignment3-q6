#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a) {
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *m_1 = BN_new();
    BIGNUM *m_2 = BN_new();
    BIGNUM *sig = BN_new();

    // Initialize n m e d
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&m_1, "49206f776520796f752024323030302e");
    BN_hex2bn(&m_2, "49206f776520796f752024333030302e");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // sign with d
    BN_mod_exp(sig, m_1, d, n, ctx);
    printBN("signed original message is ", sig);

    // sign with d
    BN_mod_exp(sig, m_2, d, n, ctx);
    printBN("signed modified message is ", sig);

    return 0;
}


