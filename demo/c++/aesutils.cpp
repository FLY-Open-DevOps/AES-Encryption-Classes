#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

void printhexDump(const char *buffer, size_t len)
{
    if (buffer == NULL || len <= 0)
    {
        return;
    }
    printf("0x%x: (len=%d)[", buffer, len);
    for (size_t i = 0; i < len; i++)
    {
        printf("%.2X ", (unsigned char)buffer[i]);
    }
    printf("]\n");
}

int main()
{
    unsigned char key[32] = "12345678901234567890123456789012";
    unsigned char *rawData = "123456";
    int rawDataLen = strlen(rawData);
    int encLen = 0;
    int outLen = 0;

    unsigned char encData[1024];
    printf("%s\n", rawData);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL, AES_ENCRYPT);
    EVP_CipherUpdate(ctx, encData, &outLen, rawData, rawDataLen);
    encLen = outLen;
    printf("%d\n", encLen);
    EVP_CipherFinal(ctx, encData + outLen, &outLen);
    encLen += outLen;
    printf("%d\n", encLen);
    EVP_CIPHER_CTX_free(ctx);
    printhexDump(encData, encLen);

    //
    int decLen = 0;
    int outlen = 0;
    unsigned char decData[1024];
    EVP_CIPHER_CTX *ctx2;
    ctx2 = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx2, EVP_aes_256_ecb(), NULL, key, NULL, AES_DECRYPT);
    EVP_CipherUpdate(ctx2, decData, &outlen, encData, encLen);
    decLen = outlen;
    EVP_CipherFinal(ctx2, decData + outlen, &outlen);
    decLen += outlen;
    EVP_CIPHER_CTX_free(ctx2);

    decData[decLen] = '\0';
    printf("decrypt: %s\n", decData);
    return 0;
}