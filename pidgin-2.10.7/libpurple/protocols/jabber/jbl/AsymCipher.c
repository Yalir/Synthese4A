#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <glib.h>

#include "AsymCipher.h"
#include "cryptron/ecies.h"

struct AsymCipher_t {
	EC_KEY *key;
	char *hex_pub;
	char *hex_priv;
};

AsymCipherRef AsymCipherCreateWithPublicKey(const char *pub_key){
	
	assert(pub_key != NULL);
	assert(strlen(pub_key) > 0);
	
	AsymCipherRef p_AsymCipher = g_malloc0(sizeof(*p_AsymCipher));	
	assert(p_AsymCipher != NULL);
	
	p_AsymCipher->hex_pub = strdup(pub_key);
	assert(p_AsymCipher->hex_pub != NULL);

	return p_AsymCipher;
}

AsymCipherRef AsymCipherCreateWithGeneratedKeyPair(){

	AsymCipherRef p_AsymCipher = g_malloc0(sizeof(*p_AsymCipher));
	assert(p_AsymCipher != NULL);	

	p_AsymCipher->key = ecies_key_create();
	assert(p_AsymCipher->key != NULL);

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
	
	secure_t *secure_t_tmp = ecies_encrypt((char *)p_AsymCipher->hex_pub, (unsigned char *)data, inputLength);
	
	*outputLength = secure_total_length(secure_t_tmp);
		
	assert(secure_t_tmp != NULL);
	assert(*outputLength > 0);

	return (void *)secure_t_tmp;
}

void * AsymCipherDecrypt(AsymCipherRef p_AsymCipher, const void *data,
                         unsigned int inputLength, unsigned long *outputLength){

	assert(p_AsymCipher != NULL);
	assert(data != NULL);
	assert(inputLength > 0);
	assert(outputLength != NULL);
	assert(p_AsymCipher->hex_priv != NULL);

	unsigned char *deciphered = ecies_decrypt((char *)p_AsymCipher->hex_priv, (secure_t *)data, outputLength);
	
	assert(deciphered != NULL);
	assert(*outputLength > 0);

	return (void *) deciphered;
}

void AsymCipherDestroy(AsymCipherRef p_AsymCipher){
	assert(p_AsymCipher != NULL);

	if (p_AsymCipher->key) {
		ecies_key_free(p_AsymCipher->key);
	}

	if (p_AsymCipher->hex_pub) {
		OPENSSL_free(p_AsymCipher->hex_pub);
	}

	if (p_AsymCipher->hex_priv) {
		OPENSSL_free(p_AsymCipher->hex_priv);
	}
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

