#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

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

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *res1 = BN_new();
    BIGNUM *res2 = BN_new();
    BIGNUM *res3 = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *n = BN_new();      // Modulus
    BIGNUM *C = BN_new();      // Ciphertext
    BIGNUM *M_original = BN_new();
    BIGNUM *M_modified = BN_new();
    BIGNUM *S_original = BN_new();
    BIGNUM *S_modified = BN_new();

    // Initialize p, q, w
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_dec2bn(&one, "1");

    // res1 = p-1
    BN_sub(res1, p, one);

    // res2 = q-1
    BN_sub(res2, q, one);

    // res3 = res1 * res2
    BN_mul(res3, res1, res2, ctx);

    // Mod-inverse: e.d mod res3 = 1
    BN_mod_inverse(d, e, res3, ctx);

    // Message to sign
    char *original_message = "I owe you $2000";
    char *modified_message = "I owe you $3000";

    // Convert messages to BIGNUMs
    BN_hex2bn(&M_original, original_message);
    BN_hex2bn(&M_modified, modified_message);

    BN_mod_exp(S_original, M_original, d, n, ctx);
    BN_mod_exp(S_modified, M_modified, d, n, ctx);
    printBN("Signature for Original Message: ", S_original);

    BN_mod_exp(S_modified, M_modified, d, n, ctx);
    printBN("Signature for Modified Message: ", S_modified);

    if (BN_cmp(S_original, S_modified) == 0) {
        printf("Signatures do not match.\n");
    } else {
        printf("Signatures match.\n");
    }

    // Free allocated memory
    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(d);
    BN_free(res1);
    BN_free(res2);
    BN_free(res3);
    BN_free(one);
    BN_free(n);
    BN_free(C);
    BN_free(M_original);
    BN_free(M_modified);
    BN_free(S_original);
    BN_free(S_modified);

    BN_CTX_free(ctx);

    return 0;
}

