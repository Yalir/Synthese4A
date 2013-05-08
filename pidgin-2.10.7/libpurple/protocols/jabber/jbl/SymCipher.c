
#include "SymCipher.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <glib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

struct SymCipher_t {
	EVP_CIPHER_CTX encryption_ctx;
	EVP_CIPHER_CTX decryption_ctx;
};

/**
 * Create an 128 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
static int aes_init(EVP_CIPHER_CTX *encryption_ctx,
             EVP_CIPHER_CTX *decryption_ctx)
{
	//int i, nrounds = 5;
	unsigned char key[16] = "azertyuiopqsdfg";
	unsigned char iv[16] = "azertyuiopqsdfg";
	
	// Init encryption context
	EVP_CIPHER_CTX_init(encryption_ctx);
	EVP_EncryptInit_ex(encryption_ctx, EVP_aes_128_cbc(), NULL, key, iv);
	
	// Init decryption context
	EVP_CIPHER_CTX_init(decryption_ctx);
	EVP_DecryptInit_ex(decryption_ctx, EVP_aes_128_cbc(), NULL, key, iv);
	
	return 0;
}

/*
 * Encrypt input_length bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
static void *aes_encrypt(EVP_CIPHER_CTX *encryption_ctx, const void *plaintext, unsigned int input_length, unsigned int *output_length)
{
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int cipher_length = input_length + AES_BLOCK_SIZE, final_length = 0;
	void *ciphertext = g_malloc(cipher_length);
	
	/* allows reusing of 'e' for multiple encryption cycles */
	EVP_EncryptInit_ex(encryption_ctx, NULL, NULL, NULL, NULL);
	
	/* update ciphertext, cipher_length is filled with the length of ciphertext generated,
	 *input_length is the size of plaintext in bytes */
	EVP_EncryptUpdate(encryption_ctx, ciphertext, &cipher_length, plaintext, input_length);
	
	/* update ciphertext with the final remaining bytes */
	EVP_EncryptFinal_ex(encryption_ctx, ciphertext+cipher_length, &final_length);
	
	*output_length = cipher_length + final_length;
	return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
static void *aes_decrypt(EVP_CIPHER_CTX *decryption_ctx, const void *ciphertext, unsigned int input_length, unsigned int *output_length)
{	
	/* because we have padding ON, we must allocate an extra cipher block size of memory */
	int myoutput_length = input_length, final_length = 0;
	void *plaintext = g_malloc(myoutput_length + AES_BLOCK_SIZE);
	
	EVP_DecryptInit_ex(decryption_ctx, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(decryption_ctx, plaintext, &myoutput_length, ciphertext, input_length);
	EVP_DecryptFinal_ex(decryption_ctx, plaintext+myoutput_length, &final_length);
	
	*output_length = myoutput_length + final_length;
	
	return plaintext;
}

SymCipherRef	SymCipherCreate(void)
{
	SymCipherRef newCipher = g_malloc(sizeof(*newCipher));
	
	if (newCipher != NULL)
	{
		memset(newCipher, 0, sizeof(*newCipher));
		
		int err = aes_init(&newCipher->encryption_ctx, &newCipher->decryption_ctx);
		
		if (err != 0)
		{
			free(newCipher), newCipher = NULL;
		}
	}
	
	return newCipher;
}

void			SymCipherDestroy(SymCipherRef aSymCipher)
{
	assert(aSymCipher != NULL);
	
	EVP_CIPHER_CTX_cleanup(&aSymCipher->encryption_ctx);
	EVP_CIPHER_CTX_cleanup(&aSymCipher->decryption_ctx);
	free(aSymCipher);
}

void *			SymCipherEncrypt(SymCipherRef aSymCipher,
								 const void *data,
								 unsigned int inputLength,
								 unsigned int *outputLength)
{
	assert(aSymCipher != NULL);
	assert(data != NULL);
	assert(inputLength > 0);
	assert(outputLength != NULL);
	
	return aes_encrypt(&aSymCipher->encryption_ctx, data, inputLength, outputLength);
}

void *			SymCipherDecrypt(SymCipherRef aSymCipher,
								 const void *data,
								 unsigned int inputLength,
								 unsigned int *outputLength)
{
	assert(aSymCipher != NULL);
	assert(data != NULL);
	assert(inputLength > 0);
	assert(outputLength != NULL);
	
	return aes_decrypt(&aSymCipher->decryption_ctx, data, inputLength, outputLength);
}
