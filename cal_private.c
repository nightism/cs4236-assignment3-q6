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
    BIGNUM *p_minus_one = BN_new();
    BIGNUM *q_minus_one = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *phi = BN_new();

    // Initialize p-1, q-1, e
    BN_hex2bn(&p_minus_one, "F7E75FDC469067FFDC4E847C51F452DE");
    BN_hex2bn(&q_minus_one, "E85CED54AF57E53E092113E62F436F4E");
    BN_hex2bn(&e, "0D88C3");

    // phi = (p-1)(q-1)
    BN_mul(phi, p_minus_one, q_minus_one, ctx);

    // ed = 1 mod phi
    BN_mod_inverse(d, e, phi, ctx);

    printBN("private key d is ", d);

    return 0;
}


