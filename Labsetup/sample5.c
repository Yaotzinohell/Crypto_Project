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

    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *S = BN_new();
    BIGNUM *M_prime = BN_new();

    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

    // Verify the signature
    BN_mod_exp(M_prime, S, e, n, ctx);

    // Print the result
    printBN("Decrypted Signature (M'): ", M_prime);

    // Original message
    char *original_message = "Launch a missile.";

    // Convert the original message to BIGNUM
    BIGNUM *M = BN_new();
    BN_bin2bn((const unsigned char *)original_message, strlen(original_message), M);

    // Compare M' with the original message M
    if (BN_cmp(M, M_prime) == 0) {
        printf("Signature is valid. Message verified.\n");
    } else {
        printf("Signature is not valid. Message verification failed.\n");
    }

    // Free allocated memory
    BN_free(e);
    BN_free(n);
    BN_free(S);
    BN_free(M);
    BN_free(M_prime);

    BN_CTX_free(ctx);

    return 0;
}
