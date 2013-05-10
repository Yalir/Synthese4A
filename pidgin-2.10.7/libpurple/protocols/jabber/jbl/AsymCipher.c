#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <glib.h>

#include "AsymCipher.h"
#include "./cryptron/ecies.h"

struct AsymCipher_t {
	// EVP_CIPHER_CTX encryption_ctx;
	// EVP_CIPHER_CTX decryption_ctx;
	EC_KEY *key;
	char *hex_pub;
	char *hex_priv;
	secure_t *ciphered;
	unsigned char *original;
/*
	typedef struct {
		typedef struct {
			uint64_t key;
			uint64_t mac;
			uint64_t orig;
			uint64_t body;
		} length;
	} secure_head_t;
*/
};

AsymCipherRef AsymCipherCreateWithPublicKey(char *pub_key){
	
	assert(pub_key != NULL);
	assert(strlen(pub_key) > 0);
	
	AsymCipherRef p_AsymCipher = g_malloc0(sizeof(*p_AsymCipher));	
	assert(p_AsymCipher != NULL);
	
	p_AsymCipher->key = ecies_key_create_private_hex(pub_key);
	assert(p_AsymCipher->key != NULL);
	assert(strlen(p_AsymCipher->key) > 0);

	return p_AsymCipher;
}

AsymCipherRef AsymCipherCreateWithGeneratedKeyPair(){

	AsymCipherRef p_AsymCipher = g_malloc0(sizeof(*p_AsymCipher));
	assert(p_AsymCipher != NULL);	

	p_AsymCipher->key = ecies_key_create();
	assert(p_AsymCipher->key != NULL);
	assert(strlen(p_AsymCipher->key) > 0);

	p_AsymCipher->hex_pub = ecies_key_public_get_hex(p_AsymCipher->key);
	p_AsymCipher->hex_priv = ecies_key_private_get_hex(p_AsymCipher->key);	
	assert(p_AsymCipher->hex_pub != NULL);
	assert(strlen(p_AsymCipher->hex_pub) > 0);
	assert(p_AsymCipher->hex_priv != NULL);
	assert(strlen(p_AsymCipher->hex_priv) > 0);
	
	return p_AsymCipher;
}

void * AsymCipherEncrypt(AsymCipherRef p_AsymCipher, const void *data,
                         unsigned int inputLength, unsigned int *outputLength){

	assert(p_AsymCipher != NULL);
	assert(data != NULL);
	assert(strlen(data) > 0);
	assert(inputLength > 0);
	assert(outputLength != NULL);

	p_AsymCipher->ciphered = ecies_encrypt(p_AsymCipher->hex_pub, (void *) data, *outputLength);
	assert(p_AsymCipher->ciphered != NULL);
	asset(strlen(p_AsymCipher->ciphered) > 0);

	return p_AsymCipher->ciphered;
}

void * AsymCipherDecrypt(AsymCipherRef p_AsymCipher, const void *data,
                         unsigned int inputLength, unsigned int *outputLength){

	assert(p_AsymCipher != NULL);
	assert(data != NULL);
	assert(strlen(data) > 0);
	assert(inputLength > 0);
	assert(outputLength != NULL);

	p_AsymCipher->original = ecies_decrypt(p_AsymCipher->hex_priv, p_AsymCipher->ciphered, outputLength);
	assert(original != NULL);
	assert(strlen(original) > 0);

	return p_AsymCipher->original;
}

void AsymCipherDestroy(AsymCipherRef p_AsymCipher){

	if (p_AsymCipher->key) {
		ecies_key_free(p_AsymCipher->key);
	}

	if (p_AsymCipher->ciphered) {
		secure_free(p_AsymCipher->ciphered);
	}

	if (p_AsymCipher->hex_pub) {
		OPENSSL_free(p_AsymCipher->hex_pub);
	}

	if (p_AsymCipher->hex_priv) {
		OPENSSL_free(p_AsymCipher->hex_priv);
	}
// Not used:
/*
	if (text) {
		free(text);
	}

	if (copy) {
		free(copy);
	}
*/
	if (p_AsymCipher->original) {
		free(p_AsymCipher->original);
	}

	return;
}

/* GETTERS & SETTERS */
char * AsymCipherGetPublicKey(AsymCipherRef p_AsymCipher){
	assert(p_AsymCipher != NULL);
	assert(p_AsymCipher->hex_pub != NULL);	
	return p_AsymCipher->hex_pub;
}
char * AsymCipherGetPrivateKey(AsymCipherRef p_AsymCipher){
	assert(p_AsymCipher != NULL);
	assert(p_AsymCipher->hex_priv != NULL);		
	return p_AsymCipher->hex_priv;
}

