#include "AsymCipher.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <glib.h>
#include <ecies.h>

struct AsymCipher_t {
	// EVP_CIPHER_CTX encryption_ctx;
	// EVP_CIPHER_CTX decryption_ctx;
	EC_KEY *key;
	char *hex_pub = NULL, *hex_priv = NULL;
	secure_t *ciphered = NULL;
	unsigned char *original;
	typedef struct {
		struct {
			uint64_t key;
			uint64_t mac;
			uint64_t orig;
			uint64_t body;
		} length;
	} secure_head_t;
};

AsymCipherRef AsymCipher_CreateWithPublicKey(){
	AsymCipherRef p_AsymCipher = g_malloc0(sizeof(*pAsymCipher));
	return p_AsymCipher;
}

AsymCipherRef AsymCipher_CreateWithKeyPair(){

	AsymCipherRef p_AsymCipher = g_malloc0(sizeof(*p_AsymCipher));

	if (!(p_AsymCipher->key = ecies_key_create())) {
		printf("Key creation failed.\n");
		// processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
		return -1;
	}

	if (!(p_AsymCipher->hex_pub = ecies_key_public_get_hex(p_AsymCipher->key)) || 
       !(p_AsymCipher->hex_priv = ecies_key_private_get_hex(p_AsymCipher->key))) {
		printf("Serialization of the key to a pair of hex strings failed.\n");
		// processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
		return -1;
	}
	
	return p_AsymCipher;
}

void * AsymCipher_Encrypt(AsymCipherRef p_AsymCipher, const void *data,
                         unsigned int inputLength, unsigned int *outputLength){

	if (!(p_AsymCipher->ciphered = ecies_encrypt(p_AsymCipher->hex_pub, (void *) data, *outputLength))) {
		printf("The encryption process failed!\n");
		// processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
		return -1;
	}
	return p_AsymCipher->ciphered;
}

void * AsymCipherDecrypt(AsymCipherRef p_AsymCipher, const void *data,
                         unsigned int inputLength, unsigned int *outputLength){

	if (!(p_AsymCipher->original = ecies_decrypt(p_AsymCipher->hex_priv, p_AsymCipher->ciphered, outputLength))) {
		printf("The decryption process failed!\n");
		// processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
		return -1;
	}
	return p_AsymCipher->original;
}

void AsymCipher_Destroy(AsymCipherRef p_AsymCipher){

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
char * AsymCipher_getHexPubKey(AsymCipherRef p_AsymCipher){ return p_AsymCipher->hex_pub; }
char * AsymCipher_getHexPrivKey(AsymCipherRef p_AsymCipher){ return p_AsymCipher->hex_priv; }
void AsymCipher_setHexPubKey(AsymCipherRef p_AsymCipher, char * hex_pub){ p_AsymCipher->hex_pub = hex_pub; }
void AsymCipher_setHexPrivKey(AsymCipherRef p_AsymCipher, char * hex_priv){ p_AsymCipher->hex_priv = hex_priv; }

