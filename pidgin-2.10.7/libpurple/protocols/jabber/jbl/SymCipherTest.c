
#include "SymCipher.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

int main()
{
	const char plaintext[] = "coucou les gens";
	unsigned plaintextLength = strlen(plaintext)+1;
	void *encrypted;
	char *decrypted;
	unsigned encryptedLength;
	unsigned decryptedLength;
	
	/** with generated key */
	SymCipherRef cipher = SymCipherCreateWithGeneratedKey();
	assert(cipher != NULL);
	
	encrypted = SymCipherEncrypt(cipher, plaintext, plaintextLength, &encryptedLength);
	assert(encrypted != NULL);
	assert(encryptedLength > 0);
	
	decrypted = SymCipherDecrypt(cipher, encrypted, encryptedLength, &decryptedLength);
	assert(decrypted != NULL);
	assert(decryptedLength > 0);
	
	assert(decryptedLength == plaintextLength);
	assert(memcmp(plaintext, decrypted, decryptedLength) == 0);
	
	/** with initialized cipher */
	void *encrypted2;
	char *decrypted2;
	unsigned encryptedLength2;
	unsigned decryptedLength2;
	SymCipherRef iniCipher = SymCipherCreateWithKey(SymCipherGetKey(cipher),
												 SymCipherGetSalt(cipher));
	assert(iniCipher != NULL);
	SymCipherDestroy(cipher);
	
	encrypted2 = SymCipherEncrypt(iniCipher, plaintext, plaintextLength, &encryptedLength2);
	assert(encrypted2 != NULL);
	assert(encryptedLength2 > 0);
	
	decrypted2 = SymCipherDecrypt(iniCipher, encrypted2, encryptedLength2, &decryptedLength2);
	assert(decrypted2 != NULL);
	assert(decryptedLength2 > 0);
	
	/** use the second symcipher to decrypt data encrypted with the first symCipher */
	char *decrypted3;
	unsigned decryptedLength3;
	
	decrypted3 = SymCipherDecrypt(iniCipher, encrypted, encryptedLength, &decryptedLength3);
	assert(decrypted3 != NULL);
	assert(decryptedLength3 > 0);
	assert(strcmp(decrypted2, decrypted3) == 0);
	
	SymCipherDestroy(iniCipher);
	
	free(encrypted);
	free(decrypted);
	free(encrypted2);
	free(decrypted2);
	return 0;
}
