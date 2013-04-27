#include "AsymCipher.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <glib.h>
#include <openssl/rsa.h>

struct SymCipher_t {
	EVP_CIPHER_CTX encryption_ctx;
	EVP_CIPHER_CTX decryption_ctx;
};


static int init_rsa(int rsaKeyLen)
{
    // Initalize contexts
    rsaEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    rsaDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
 
    if(rsaEncryptCtx == NULL || rsaDecryptCtx == NULL) {
        return FAILURE;
    }

    EVP_CIPHER_CTX_init(rsaEncryptCtx);
    EVP_CIPHER_CTX_init(rsaDecryptCtx);
 
    // Init RSA
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
 
    if(EVP_PKEY_keygen_init(ctx) <= 0) {
        return FAILURE;
    }
 
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)rsaKeyLen) <= 0) {
        return FAILURE;
    }
 
    if(EVP_PKEY_keygen(ctx, &serverKeypair) <= 0) {
        return FAILURE;
    }
 
    EVP_PKEY_CTX_free(ctx);
 
    rsaSymKey = (unsigned char*)malloc(rsaKeyLen/8);
    rsaIV = (unsigned char*)malloc(EVP_MAX_IV_LENGTH);
 
    return SUCCESS;
}

