
#ifndef ASYMCIPHER_H
#define ASYMCIPHER_H

typedef struct AsymCipher_t *AsymCipherRef;

/** @brief Create a new asymetric cipher handle from a given public key
 *
 * @return a ready to used cipher object
 */
AsymCipherRef AsymCipherCreateWithPublicKey(char *pub_key);

/** @brief Create a new asymetric cipher handle from a given key pair
 *
 * @return a ready to used cipher object
 */
AsymCipherRef AsymCipherCreateWithKeyPair(char *priv_key, char *pub_key);

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
 * @param aAsymCipher the cipher handle to destroy
 */
void AsymCipherDestroy(AsymCipherRef p_AsymCipher);


/** @brief Encrypt the given data @a data of length @a inputLength
 *
 * Preconditions:
 * - aAsymCipher must be a valid cipher handle
 * - data must not be null
 * - inputLength must be greater than 0
 * - outputLength must not be null
 *
 * @param aAsymCipher the cipher handle to use for encryption
 * @param data the data to encrypt
 * @param inputLength the length of the data to encrypt, in bytes
 * @param outputLength the length of the returned encrypted data
 * @return the encrypted data, or NULL if an error occured. You're responsible for g_freeing this data
 */
void * AsymCipherEncrypt(AsymCipherRef p_AsymCipher, const void *data,
                         unsigned int inputLength, unsigned int *outputLength);


/** @brief Decrypt the given data @a data of length @a inputLength
 *
 * Preconditions:
 * - aAsymCipher must be a valid cipher handle
 * - data must not be null
 * - inputLength must be greater than 0
 * - outputLength must not be null
 *
 * @param aAsymCipher the cipher handle to use for decryption
 * @param data the data to decrypt
 * @param inputLength the length of the data to decrypt, in bytes
 * @param outputLength the length of the returned decrypted data
 * @return the encrypted data, or NULL if an error occured. You're responsible for g_freeing this data
 */
void * AsymCipherDecrypt(AsymCipherRef p_AsymCipher, const void *data,
                         unsigned int inputLength, unsigned int *outputLength);

const char * AsymCipherGetPublicKey(AsymCipherRef p_AsymCipher);
const char * AsymCipherGetPrivateKey(AsymCipherRef p_AsymCipher);

#endif
