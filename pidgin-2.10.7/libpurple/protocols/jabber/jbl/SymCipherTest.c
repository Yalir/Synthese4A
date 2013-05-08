
#include "SymCipher.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

static
void printb(const char *data, unsigned int length)
{
	unsigned i;
	for (i = 0;i < length;i++)
		printf("%.02x ", (unsigned char)data[i]);
	puts("");
}

int main()
{
	const char plaintext[] = "coucou les gens";
	unsigned plaintextLength = strlen(plaintext)+1;
	SymCipherRef cipher = SymCipherCreate();
	void *encrypted;
	char *decrypted;
	unsigned encryptedLength;
	unsigned decryptedLength;
	
	assert(cipher != NULL);
	
	printf("Original plaintext:<%s>\n", plaintext);
	printb(plaintext, plaintextLength);
	
	printf("SymCipherEncrypt(%p, %s, %u, %p)\n", cipher, plaintext, plaintextLength, &encryptedLength);
	encrypted = SymCipherEncrypt(cipher, plaintext, plaintextLength, &encryptedLength);
	
	printf("Encrypted data (%u bytes):\n", encryptedLength);
	printb(encrypted, encryptedLength);
	
	printf("SymCipherDecrypt(%p, data, %u, %p)\n", cipher, encryptedLength, &decryptedLength);
	decrypted = SymCipherDecrypt(cipher, encrypted, encryptedLength, &decryptedLength);
	
	printf("Decrypted data (%u bytes):\n", decryptedLength);
	printb(decrypted, decryptedLength);
	
	printf("Decrypted:%s\n", (char *)decrypted);
	
	SymCipherDestroy(cipher);
	
	assert(decryptedLength == plaintextLength);
	assert(memcmp(plaintext, decrypted, decryptedLength) == 0);
	
	free(encrypted);
	free(decrypted);
	return 0;
}
