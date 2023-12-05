#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

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
    BIGNUM *d = BN_new();  // Private key
    BIGNUM *C = BN_new();  // Ciphertext
    BIGNUM *M = BN_new();  // Resultant decrypted message

    // Initialize n, e, C (ciphertext)
    BN_hex2bn(&n,"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e,"010001");
    BN_hex2bn(&C,"8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    // Assuming you have the private key 'd'
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");  	

    // Calculate M = C^d mod n
    BN_mod_exp(M, C, d, n, ctx);

    // Convert the result to ASCII
    char *ascii_message = BN_bn2hex(M);
    printf("Decrypted Message (ASCII): %s\n", ascii_message);

    // Free allocated memory
    OPENSSL_free(ascii_message);

    return 0;
}

