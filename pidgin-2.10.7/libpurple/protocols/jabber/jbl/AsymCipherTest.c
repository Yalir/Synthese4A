#include "AsymCipher.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "./cryptron/ecies.h"

static
void printKey(const char *key){
	
	int i;
	int length = strlen(key);
	for(i=0 ; i<length ; i++){
		printf("%.02x ", (unsigned char)key[i]);
	}
	puts("");
}

static
void printSecure_t (secure_t *sec){
	char *donnees = (char *)secure_body_data(sec);
	uint64_t len = secure_body_length(sec);
	int i;
	for(i=0 ; i<len ; i++){
			printf("%.02x ", (unsigned char)donnees[i]);
	}
	puts("");
}

int main(){

	AsymCipherRef p_AsymCipher = AsymCipherCreateWithGeneratedKeyPair();
	assert(p_AsymCipher != NULL);

	const char * pub_key = AsymCipherGetPublicKey(p_AsymCipher);
	assert(pub_key != NULL);
	assert(strlen(pub_key) > 0);
	
	const char * priv_key = AsymCipherGetPrivateKey(p_AsymCipher);
	assert(priv_key != NULL);
	assert(strlen(priv_key) > 0);

	char *data = "True random data";
	unsigned long outputLength = 0;
	secure_t *ciphered = AsymCipherEncrypt(p_AsymCipher, data, strlen(data)+1, &outputLength);
	assert(ciphered != NULL);
	assert(outputLength > 0);
	
	char * original = AsymCipherDecrypt(p_AsymCipher, ciphered, outputLength, &outputLength);
	assert(original != NULL);
	
	assert(strcmp(original, data) == 0);


	AsymCipherRef p_AsymCipherRefWithPublicKey = AsymCipherCreateWithPublicKey(pub_key);
	assert(p_AsymCipherRefWithPublicKey != NULL);
	
	free(ciphered);
	ciphered = AsymCipherEncrypt(p_AsymCipherRefWithPublicKey, data, strlen(data)+1, &outputLength);
	assert(ciphered != NULL);
	
	free(original);
	original = AsymCipherDecrypt(p_AsymCipher, ciphered, outputLength, &outputLength);
	assert(original != NULL);
	
	assert(strcmp(original, data) == 0);

	AsymCipherDestroy(p_AsymCipher);
	assert(p_AsymCipher == NULL);
	
	AsymCipherDestroy(p_AsymCipherRefWithPublicKey);
	assert(p_AsymCipherRefWithPublicKey == NULL);
	
	return 0;
}
