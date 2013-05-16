#include "AsymCipher.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "cryptron/ecies.h"


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
	
	AsymCipherDestroy(p_AsymCipherRefWithPublicKey);
	
	return 0;
}
