#include "AsymCipher.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

static
void printKey(char *key){
	
	int i;
	int length = strlen(key);
	for(i=0 ; i<length ; i++){
		printf("%.02x ", (unsigned char)key[i]);
	}
	puts("");
}

int main(){

	printf("AsymCipherCreateWithGeneratedKeyPair...\n");
	AsymCipherRef p_AsymCipher = AsymCipherCreateWithGeneratedKeyPair();
	char * pub_key = AsymCipherGetPublicKey(p_AsymCipher);
	char * priv_key = AsymCipherGetPrivateKey(p_AsymCipher);
	printf("Public key created: ");
	printKey(pub_key);
	printf("Private key created: ");
	printKey(priv_key);

	AsymCipherRef p_AsymCipherRefWithPublicKey = AsymCipherCreateWithPublicKey(pub_key);
	printf("Private key created with public key: ");
	printKey(p_AsymCipherRefWithPublicKey->priv_key);
	printf("Destroying asymCipher...\n");
	AsymCipherDestroy(p_AsymCipher);
	AsymCipherDestroy(p_AsymCipherRefWithPublicKey);
	return 0;
}
