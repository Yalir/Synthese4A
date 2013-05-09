
#ifndef ASYMCIPHER_H
#define ASYMCIPHER_H

typedef struct AsymCipher_t *AsymCipherRef;


//#warning AsymCipherRef AsymCipherCreate(void);
#warning AsymCipherRef AsymCipherCreateWithPublicKey(char *pub_key);
#warning AsymCipherRef AsymCipherCreateWithKeyPair(char *priv_key, char *pub_key);
#warning AsymCipherRef AsymCipherCreateWithGeneratedKeyPair(void);
//#warning AsymCipherRef AsymCipherGenerateKeyPair(AsymCipherRef asymCipher);

/** @brief Create a new asymetric cipher handle
 *
 * @return a ready to used cipher object, or NULL is an error occured
 */
AsymCipherRef AsymCipher_CreateWithPublicKey(void);

/** @brief Create a new asymetric cipher handle
 *
 * @return a ready to used cipher object, or NULL is an error occured
 */
AsymCipherRef AsymCipher_CreateWithKeyPair(void);


/** @brief Destroy a asymetric cipher handle
 *
 * Preconditions:
 * - aAsymCipher must be a valid cipher handle
 *
 * @param aAsymCipher the cipher handle to destroy
 */
#warning => AsymCipherDestroy
void AsymCipher_Destroy(AsymCipherRef p_AsymCipher);


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
#warning AsymCipherEncrypt
void * AsymCipher_Encrypt(AsymCipherRef p_AsymCipher, const void *data,
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

#warning => AsymCipherGetPublicKey
char * AsymCipher_getHexPubKey(AsymCipherRef p_AsymCipher);
#warning => AsymCipherGetPrivateKey
char * AsymCipher_getHexPrivKey(AsymCipherRef p_AsymCipher);


#endif
