#include "AsymCipher.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <glib.h>

struct SymCipher_t {
	EVP_CIPHER_CTX encryption_ctx;
	EVP_CIPHER_CTX decryption_ctx;
};
