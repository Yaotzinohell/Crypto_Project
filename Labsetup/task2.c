#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a)
{
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *M = BN_new();  // Original message
    BIGNUM *C = BN_new();  // Encrypted message

    // Initialize public key and message
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&M, "A top secret!");

    // Encrypt the message
    BN_mod_exp(C, M, e, n, ctx);

    // Print the encrypted message
    printBN("Encrypted Message (C): ", C);

    // Free allocated memory
    BN_free(n);
    BN_free(e);
    BN_free(M);
    BN_free(C);

    BN_CTX_free(ctx);

    return 0;
}

