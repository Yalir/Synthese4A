
#ifndef SYMCIPHER_H
#define SYMCIPHER_H

typedef struct SymCipher_t *SymCipherRef;

/** @brief Create a new symetric cipher handle and generate a secret key
 *
 * @return a ready to used cipher object, or NULL is an error occured
 */
SymCipherRef	SymCipherCreateWithGeneratedKey(void);

/** @brief Create a new symetric cipher handle with the key @a keyData
 *
 * Preconditions:
 * - secretKey must be a valid hexadecimal string
 *
 * @param keyHex the 128 bytes key to use for secret key generation for
 * the symetric cipher, as an hexadecimal string
 * @param saltHex the 8 bytes salt to use for secret key generation for
 * the symetric cipher, as an hexadecimal string
 * @return a valid symetric cipher handle
 */
SymCipherRef	SymCipherCreateWithKey(const char *keyHex,
									   const char *saltHex);


/** @brief Destroy a symetric cipher handle
 *
 * Preconditions:
 * - aSymCipher must be a valid cipher handle
 *
 * @param aSymCipher the cipher handle to destroy
 */
void			SymCipherDestroy(SymCipherRef aSymCipher);


/** @brief Return the key used to generate the secret as an hexadecimal string
 *
 * Preconditions:
 * - aSymCipher must be a valid cipher handle
 *
 * @param aSymCipher the cipher handle to get the key from
 * @return the generation key as an hexadecimal string, you're responsible for
 * g_freeing this string
 */
char *			SymCipherGetKey(SymCipherRef aSymCipher);


/** @brief Return the salt used to generate the secret as an hexadecimal string
 *
 * Preconditions:
 * - aSymCipher must be a valid cipher handle
 *
 * @param aSymCipher the cipher handle to get the salt from
 * @return the salt as an hexadecimal string, you're responsible for
 * g_freeing this string
 */
char *			SymCipherGetSalt(SymCipherRef aSymCipher);


/** @brief Encrypt the given data @a data of length @a inputLength
 *
 * Preconditions:
 * - aSymCipher must be a valid cipher handle
 * - data must not be null
 * - inputLength must be greater than 0
 * - outputLength must not be null
 *
 * @param aSymCipher the cipher handle to use for encryption
 * @param data the data to encrypt
 * @param inputLength the length of the data to encrypt, in bytes
 * @param outputLength the length of the returned encrypted data
 * @return the encrypted data, or NULL if an error occured. You're responsible for g_freeing this data
 */
void *			SymCipherEncrypt(SymCipherRef aSymCipher,
								 const void *data,
								 unsigned int inputLength,
								 unsigned int *outputLength);


/** @brief Decrypt the given data @a data of length @a inputLength
 *
 * Preconditions:
 * - aSymCipher must be a valid cipher handle
 * - data must not be null
 * - inputLength must be greater than 0
 * - outputLength must not be null
 *
 * @param aSymCipher the cipher handle to use for decryption
 * @param data the data to decrypt
 * @param inputLength the length of the data to decrypt, in bytes
 * @param outputLength the length of the returned decrypted data
 * @return the encrypted data, or NULL if an error occured. You're responsible for g_freeing this data
 */
void *			SymCipherDecrypt(SymCipherRef aSymCipher,
								 const void *data,
								 unsigned int inputLength,
								 unsigned int *outputLength);

#endif
