#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <glib.h>

#include "AsymCipher.h"
#include "./cryptron/ecies.h"

struct AsymCipher_t {
	EC_KEY *key;
	const char *hex_pub;
	const char *hex_priv;
	secure_t *cipher;
};

AsymCipherRef AsymCipherCreateWithPublicKey(const char *pub_key){
	
	assert(pub_key != NULL);
	assert(strlen(pub_key) > 0);
	
	AsymCipherRef p_AsymCipher = g_malloc0(sizeof(*p_AsymCipher));	
	assert(p_AsymCipher != NULL);
	
	p_AsymCipher->hex_pub = strdup(pub_key);
	assert(p_AsymCipher->hex_pub != NULL);
	//assert(strlen(p_AsymCipher->key) > 0);

	return p_AsymCipher;
}

AsymCipherRef AsymCipherCreateWithGeneratedKeyPair(){

	AsymCipherRef p_AsymCipher = g_malloc0(sizeof(*p_AsymCipher));
	assert(p_AsymCipher != NULL);	

	p_AsymCipher->key = ecies_key_create();
	assert(p_AsymCipher->key != NULL);
	//assert(strlen(p_AsymCipher->key) > 0);

	p_AsymCipher->hex_pub = ecies_key_public_get_hex(p_AsymCipher->key);
	p_AsymCipher->hex_priv = ecies_key_private_get_hex(p_AsymCipher->key);	
	assert(p_AsymCipher->hex_pub != NULL);
	assert(strlen(p_AsymCipher->hex_pub) > 0);
	assert(p_AsymCipher->hex_priv != NULL);
	assert(strlen(p_AsymCipher->hex_priv) > 0);
	
	return p_AsymCipher;
}

void * AsymCipherEncrypt(AsymCipherRef p_AsymCipher, const void *data,
                         unsigned int inputLength, unsigned long *outputLength){

	assert(p_AsymCipher != NULL);
	assert(data != NULL);
	assert(inputLength > 0);
	assert(outputLength != NULL);
	assert(p_AsymCipher->hex_pub != NULL);

	p_AsymCipher->ciphered = ecies_encrypt((char *)p_AsymCipher->hex_pub, (unsigned char *)data, inputLength);
	*outputLength = secure_body_length(p_AsymCipher->ciphered);	
		
	assert(p_AsymCipher->ciphered != NULL);
	assert(outputLength > 0);

	return secure_ p_AsymCipher->ciphered;
}

void * AsymCipherDecrypt(AsymCipherRef p_AsymCipher, const void *data,
                         unsigned int inputLength, unsigned long *outputLength){

	assert(p_AsymCipher != NULL);
	assert(data != NULL);
	assert(inputLength > 0);
	assert(outputLength != NULL);
	assert(p_AsymCipher->hex_priv != NULL);

	unsigned char *deciphered = ecies_decrypt((char *)p_AsymCipher->hex_priv, data, outputLength);
	assert(deciphered != NULL);

	return deciphered;
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

/* GETTERS */
const char * AsymCipherGetPublicKey(AsymCipherRef p_AsymCipher){
	assert(p_AsymCipher != NULL);
	assert(p_AsymCipher->hex_pub != NULL);	
	return p_AsymCipher->hex_pub;
}
const char * AsymCipherGetPrivateKey(AsymCipherRef p_AsymCipher){
	assert(p_AsymCipher != NULL);
	assert(p_AsymCipher->hex_priv != NULL);		
	return p_AsymCipher->hex_priv;
}

