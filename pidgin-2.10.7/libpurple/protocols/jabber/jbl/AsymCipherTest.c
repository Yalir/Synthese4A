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
			printf("%.02x ", donnees[i]);
	}
	puts("");
}

int main(){

	printf("AsymCipherCreateWithGeneratedKeyPair...\n");
	AsymCipherRef p_AsymCipher = AsymCipherCreateWithGeneratedKeyPair();
	const char * pub_key = AsymCipherGetPublicKey(p_AsymCipher);
	const char * priv_key = AsymCipherGetPrivateKey(p_AsymCipher);
	printf("Public key created: ");
	printKey(pub_key);
	printf("Private key created: ");
	printKey(priv_key);
	printf("Ciphering...\n");
	char *data = "Random data, high as fuck!";
	unsigned long outputLength = 0;
	secure_t *ciphered = AsymCipherEncrypt(p_AsymCipher, data, strlen(data), &outputLength);
	printf("Plaintext: ");
	printKey(data);
	printf("Ciphered text: ");
	printSecure_t(ciphered);
	printf("Ciphered length: %ld\n", outputLength);
	char * original = AsymCipherDecrypt(p_AsymCipher, data, outputLength, &outputLength);
	printf("Deciphered: ");
	printKey(original);

	//AsymCipherRef p_AsymCipherRefWithPublicKey = AsymCipherCreateWithPublicKey(pub_key);
	//printf("Private key created with public key: ");
	//printKey(AsymCipherGetPublicKey(p_AsymCipherRefWithPublicKey));
	//printf("Destroying asymCipher...\n");
	//AsymCipherDestroy(p_AsymCipher);
	//AsymCipherDestroy(p_AsymCipherRefWithPublicKey);

	
	return 0;
}
