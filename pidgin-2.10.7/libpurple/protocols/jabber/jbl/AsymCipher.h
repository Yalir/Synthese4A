
#ifndef ASYMCIPHER_H
#define ASYMCIPHER_H

typedef struct AsymCipher_t *AsymCipherRef;

/** @brief Create a new asymetric cipher handle from a given public key
 *
 * @return a ready to used cipher object
 */
AsymCipherRef AsymCipherCreateWithPublicKey(const char *pub_key);

/** @brief Create a new asymetric cipher handle
 *
 * @return a ready to used cipher object
 */
AsymCipherRef AsymCipherCreateWithGeneratedKeyPair(void);

/** @brief Destroy a asymetric cipher handle
 *
 * Preconditions:
 * - aAsymCipher must be a valid cipher handle
 *
 * @param AsymCipherRef the cipher handle to destroy
 */
void AsymCipherDestroy(AsymCipherRef p_AsymCipher);


/** @brief Encrypt the given data @a data of length @a inputLength
 *
 * Preconditions:
 * - AsymCipherRef must be a valid cipher handle
 * - data must not be null
 * - inputLength must be greater than 0
 * - outputLength must not be null
 *
 * @param AsymCipherRef the cipher handle to use for encryption
 * @param data the data to encrypt
 * @param inputLength the length of the data to encrypt, in bytes
 * @param outputLength the length of the returned encrypted data
 * @return the encrypted data, or NULL if an error occured. You're responsible for g_freeing this data
 */
void * AsymCipherEncrypt(AsymCipherRef p_AsymCipher, const void *data,
                         unsigned int inputLength, unsigned long *outputLength);


/** @brief Decrypt the given data @a data of length @a inputLength
 *
 * Preconditions:
 * - AsymCipherRef must be a valid cipher handle
 * - data must not be null
 * - inputLength must be greater than 0
 * - outputLength must not be null
 *
 * @param AsymCipherRef the cipher handle to use for decryption
 * @param data the data to decrypt
 * @param inputLength the length of the data to decrypt, in bytes
 * @param outputLength the length of the returned decrypted data
 * @return the encrypted data, or NULL if an error occured. You're responsible for g_freeing this data
 */
void * AsymCipherDecrypt(AsymCipherRef p_AsymCipher, const void *data,
                         unsigned int inputLength, unsigned long *outputLength);

/** @brief Return the public key of the AsymCipher @a p_AsymCipher
 *
 * Preconditions:
 * - p_AsymCipher must be a valid cipher handle
 *
 * @param p_AsymCipher the cipher handle from which we want the public key
 * @return the public key of the AsymCipher as an hexadecimal string.
 */
const char * AsymCipherGetPublicKey(AsymCipherRef p_AsymCipher);


/** @brief Return the private key of the AsymCipher @a p_AsymCipher
 *
 * Preconditions:
 * - p_AsymCipher must be a valid cipher handle
 *
 * @param p_AsymCipher the cipher handle from which we want the private key
 * @return the private key of the AsymCipher as an hexadecimal string.
 */
const char * AsymCipherGetPrivateKey(AsymCipherRef p_AsymCipher);

#endif
