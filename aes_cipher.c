

//Openssl_test_cipher( (EVP_CIPHER *) EVP_aes_128_ctr() );
void Openssl_test_cipher( const EVP_CIPHER *algo_and_mode)
{

	size_t key_size;
	size_t iv_size;
	int output_size;
	uint8_t *iv;
	uint8_t *key;
	uint8_t *clear;
	uint8_t *ciphertext;
	EVP_CIPHER_CTX aes_ctx;
		
	// Allocate clear and ciphertext buffers
	clear = (uint8_t *) malloc(C_buffer_size);
	ciphertext = (uint8_t *) malloc(C_buffer_size);

	// Init Cipher ctx
	EVP_CIPHER_CTX_init(&aes_ctx);

	// Setup parameters
	iv_size = EVP_CIPHER_iv_length(algo_and_mode);
	iv = (uint8_t*) malloc(iv_size);
	key_size = EVP_CIPHER_key_length(algo_and_mode);
	key = (uint8_t*) malloc(key_size);

	// Init Cipher
	 EVP_EncryptInit(&aes_ctx, algo_and_mode, (unsigned char*)key, (unsigned char*)iv)

	// Feed the Cipher
	EVP_EncryptUpdate(&aes_ctx, ciphertext, &output_size, clear, C_buffer_size)
	EVP_EncryptFinal_ex(&aes_ctx, ciphertext, &output_size)

	// Get stop time
	clock_gettime(CLOCK_MONOTONIC, &stop_time);

	// Cleanup
	EVP_CIPHER_CTX_cleanup(&aes_ctx);
	free(iv);
	free(key);
	free(clear);
	free(ciphertext);

}


