
#ifndef SYMCIPHER_H
#define SYMCIPHER_H

typedef struct SymCipher_t *SymCipherRef;

/** @brief Create a new symetric cipher handle
 *
 * @return a ready to used cipher object, or NULL is an error occured
 */
SymCipherRef	SymCipherCreate(void);


/** @brief Destroy a symetric cipher handle
 *
 * Preconditions:
 * - aSymCipher must be a valid cipher handle
 *
 * @param aSymCipher the cipher handle to destroy
 */
void			SymCipherDestroy(SymCipherRef aSymCipher);


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
 * @return the encrypted data, or NULL if an error occured. You're responsible for freeing this data
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
 * @return the encrypted data, or NULL if an error occured. You're responsible for freeing this data
 */
void *			SymCipherDecrypt(SymCipherRef aSymCipher,
								 const void *data,
								 unsigned int inputLength,
								 unsigned int *outputLength);

#endif
