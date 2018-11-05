#include <stdio.h>
#include <string.h>
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
    BIGNUM *n = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *ver = BN_new();

    // Initialize n m e d
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&m, "4c61756e63682061206d697373696c652e");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

    // verify with e
    BN_mod_exp(ver, s, e, n, ctx);
    printBN("verified msg is: ", ver);
    printBN("original msg is: ", m);
    if (strcmp(BN_bn2hex(m), BN_bn2hex(ver)) == 0)
        printf("Verfication succeeds!\n");
    else
        printf("Verfication fails!\n");

    // signature corrupted
    printf("\nIf signature corrupted:\n");
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    BN_mod_exp(ver, s, e, n, ctx);
    printBN("verified msg is: ", ver);
    printBN("original msg is: ", m);
    if (strcmp(BN_bn2hex(m), BN_bn2hex(ver)) == 0)
        printf("Verfication succeeds!\n");
    else
        printf("Verfication fails!\n");

    return 0;
}


