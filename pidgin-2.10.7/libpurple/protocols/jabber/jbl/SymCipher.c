
#include "SymCipher.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <glib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "../../../util.h"

struct SymCipher_t {
	EVP_CIPHER_CTX encryption_ctx;
	EVP_CIPHER_CTX decryption_ctx;
	unsigned char keyData[SYMCIPHER_KEY_LENGTH];
	unsigned char salt[SYMCIPHER_SALT_LENGTH];
};

static void SecureRandFill(unsigned char *buffer, size_t l) {
	// TODO: replace with RAND_bytes and feed the generator with a good entropy
	// source
	if (!RAND_pseudo_bytes(buffer, l)) {
		fprintf(stderr, "Warning: the generated pseudo random number is not"
				" cryptographically strong\n");
	}
}

/**
 * Create an 128 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
static int aes_init(EVP_CIPHER_CTX *encryption_ctx,
					EVP_CIPHER_CTX *decryption_ctx,
					const unsigned char *keyData,
					unsigned int keyDataLength,
					const unsigned char salt[SYMCIPHER_SALT_LENGTH])
{
	int i, nrounds = 5;
	unsigned char key[16];
	unsigned char iv[16];
	
	/* Gen key & IV for AES 128 CBC mode. A SHA1 digest is used to hash the
	 * supplied key material.
	 * nrounds is the number of times the we hash the material. More rounds
	 * are more secure but slower.
	 */
	i = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(),
					   salt, keyData, keyDataLength,
					   nrounds, key, iv);
	if (i * 8 != 128) {
		printf("Key size is %d bits - should be 128 bits\n", i * 8);
		return -1;
	}
	
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

SymCipherRef	SymCipherCreateWithGeneratedKey(void)
{
	SymCipherRef newCipher = g_malloc0(sizeof(*newCipher));
	
	if (newCipher != NULL)
	{
		SecureRandFill(newCipher->keyData, sizeof(newCipher->keyData));
		SecureRandFill(newCipher->salt, sizeof(newCipher->salt));
		
		int err = aes_init(&newCipher->encryption_ctx, &newCipher->decryption_ctx,
						   newCipher->keyData, sizeof(newCipher->keyData),
						   newCipher->salt);
		
		if (err != 0)
		{
			free(newCipher), newCipher = NULL;
		}
	}
	
	return newCipher;
}

SymCipherRef	SymCipherCreateWithKey(const char *keyHex,
									   const char *saltHex)
{
	SymCipherRef newCipher = g_malloc0(sizeof(*newCipher));
	
	if (newCipher != NULL)
	{
		unsigned long keyLength = 0;
		// guchar *purple_base16_decode(const char *str, gsize *ret_len)
		unsigned char *keyBuffer = purple_base16_decode(keyHex, &keyLength);
		assert(keyLength == SYMCIPHER_KEY_LENGTH);
		
		unsigned long saltLength = 0;
		unsigned char *saltBuffer = purple_base16_decode(saltHex, &saltLength);
		assert(saltLength == SYMCIPHER_SALT_LENGTH);
		
		memcpy(newCipher->keyData, keyBuffer, SYMCIPHER_KEY_LENGTH);
		memcpy(newCipher->salt, saltBuffer, SYMCIPHER_SALT_LENGTH);
		
		g_free(keyBuffer);
		g_free(saltBuffer);
		
		int err = aes_init(&newCipher->encryption_ctx, &newCipher->decryption_ctx,
						   newCipher->keyData, sizeof(newCipher->keyData),
						   newCipher->salt);
		
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
	g_free(aSymCipher);
}

char*			SymCipherGetKey(SymCipherRef aSymCipher)
{
	assert(aSymCipher != NULL);
	return purple_base16_encode(aSymCipher->keyData, sizeof(aSymCipher->keyData));
}

char*			SymCipherGetSalt(SymCipherRef aSymCipher)
{
	assert(aSymCipher != NULL);
	return purple_base16_encode(aSymCipher->salt, sizeof(aSymCipher->salt));
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
