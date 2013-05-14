
#include "../../../connection.h"
#include "ProtocolHandler.h"
#include "ProtocolHandlerPriv.h"
#include "AsymCipher.h"
#include "SymCipher.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <glib.h>

#pragma mark MessageHandlerTab
static MessageHandler messageHandlers[EndEnumCode] =
{
	BadMessageHandler,             // 0
	StopEncryptionHandler,         // 1
	PublicKeyRequestHandler,       // 2
	PublicKeyMessageHandler,       // 3
	PublicKeyAnswerHandler,        // 4
	PublicKeyAlreadyKnownHandler,  // 5
	SecretKeyTransmissionHandler,       // 6
	SecretKeyAnswerHandler,        // 7
	EncryptedUserMessageHandler,   // 8
};

// Serialize a message with the given structure
static char *StructuredMessagePack(StructuredMessage message)
{
	void *finalBuffer = g_malloc(message.dataLength + 1);
	
	// Append objects
	memcpy(finalBuffer, &message.code, 1);
	
	if (message.dataLength > 0)
		memcpy(finalBuffer + 1, message.data, message.dataLength);
	
	//printf("StructuredMessagePack )
	
	gchar *encoded = purple_base64_encode(finalBuffer, message.dataLength + 1);
	g_free(finalBuffer);
	
	printf("StructuredMessagePack encoded length = %d\n", strlen(encoded)+1);
	
	return encoded;
}

// Deserialize a StructuredMessage from the given base64 data
static StructuredMessage StructuredMessageExtract(const char *b64Data, gboolean *success)
{
	assert(b64Data != NULL);
	assert(success != NULL);
	
	StructuredMessage message = {0, NULL, 0};
	
	gsize decodedLength = 0;
	guchar *decoded = purple_base64_decode(b64Data, &decodedLength);
	
	if (0 == decodedLength)
		*success = FALSE;
	else {
		*success = TRUE;
		memcpy(&message.code, decoded, 1);
		
		printf("StructuredMessageExtract decoded length = %d\n", decodedLength);
		
		if (decodedLength > 1) {
			char *dataBuffer = g_malloc(decodedLength-1);
			message.data = dataBuffer;
			memcpy(dataBuffer, decoded + 1, decodedLength-1);
			message.dataLength = decodedLength-1;
		}
	}
	
	g_free(decoded);
	
	return message;
}

static void StructuredMessageSend(StructuredMessage structured,
								  PurpleConversation *conv)
{
	// Serialize message
	char *serialized = StructuredMessagePack(structured);
	
	// Send it
	purple_conv_im_send(PURPLE_CONV_IM(conv), serialized);
	
	// Clean
	g_free(serialized);
}


#pragma mark
#pragma mark Protocol handler
#pragma mark

#pragma mark Protocol strings

const char *LetsEnableEncryptionRequestString = ":lets-enable-encryption";
const char *LetsEnableEncryptionOkAnswerString = ":ok-lets-encrypt";
const char *LetsEnableEncryptionNokAnswerString = ":no-i-dont-want-to";
const char *NOKString = "NOK";
const char *OKString = "OK";

#pragma mark Protocol struct

struct ProtocolHandler_t {
	gboolean encryption_enabled;
	AsymCipherRef localAsymCipher;
	AsymCipherRef peerAsymCipher;
	SymCipherRef symCipher;
	ProtocolStep validatedStep;
};

#pragma mark Protocol public functions

ProtocolHandlerRef ProtocolHandlerCreate(void)
{
	puts(__FUNCTION__);
	ProtocolHandlerRef handler = g_malloc0(sizeof(*handler));
	
	if (handler) {
		handler->encryption_enabled = FALSE;
		handler->localAsymCipher = AsymCipherCreateWithGeneratedKeyPair();
	}
	
	return handler;
}

void ProtocolHandlerDestroy(ProtocolHandlerRef aHandler)
{
    assert(aHandler != NULL);
	
	if (aHandler->localAsymCipher)
		AsymCipherDestroy(aHandler->localAsymCipher);
	if (aHandler->peerAsymCipher)
		AsymCipherDestroy(aHandler->peerAsymCipher);
	if (aHandler->symCipher)
		SymCipherDestroy(aHandler->symCipher);
	
	g_free(aHandler);
}

gboolean ProtocolHandlerHandleInput(ProtocolHandlerRef aHandler,
                                    PurpleConnection *gc,
                                    const char *who,
                                    const char *original_msg,
                                    char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(gc != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(original_msg != NULL);
	assert(strlen(original_msg) > 0);
	assert(modified_input_msg != NULL);
	
	//puts(__FUNCTION__);
	
	PurpleConversation *conv = purple_find_conversation_with_account
	(PURPLE_CONV_TYPE_IM, who, gc->account);
	
	if (!conv) {
		fprintf(stderr, "ProtocolHandlerHandleInput: Could not find conv for %s\n",
				who);
		return FALSE;
	}
	
	if (aHandler->validatedStep == NotYetStartedStep &&
		strcmp(original_msg, LetsEnableEncryptionRequestString) == 0) {
		// We received a request to enable encryption
		
		if (aHandler->encryption_enabled == TRUE) {
			// Encryption already enabled, refuse!
			purple_conv_im_send(PURPLE_CONV_IM(conv), LetsEnableEncryptionNokAnswerString);
		} else {
			purple_conv_im_send(PURPLE_CONV_IM(conv), LetsEnableEncryptionOkAnswerString);
			aHandler->validatedStep = LetsEnableEncryptionAnswerStep;
		}
		
		*modified_input_msg = NULL;
		return TRUE;
	} else if (aHandler->validatedStep == LetsEnableEncryptionRequestStep &&
			   (strcmp(original_msg, LetsEnableEncryptionOkAnswerString) == 0 ||
				strcmp(original_msg, LetsEnableEncryptionNokAnswerString) == 0))
	{
		if (strcmp(original_msg, LetsEnableEncryptionNokAnswerString) == 0) {
			// Peer refuses encryption, abort protocol
			*modified_input_msg = NULL;
			aHandler->validatedStep = NotYetStartedStep;
			return TRUE;
		} else {
			// Skip step 4 (assume we never know the public key)
			// Do step 5
			StructuredMessage msg = {PublicKeyRequestCode, NULL, 0};
			char *data = StructuredMessagePack(msg);
			
			purple_conv_im_send(PURPLE_CONV_IM(conv), (const char *)data);
			g_free(data);
			aHandler->validatedStep = ItsPublicKeyRequestStep;
			*modified_input_msg = NULL;
			return TRUE;
		}
	} else {
		gboolean success;
		StructuredMessage structured = StructuredMessageExtract(original_msg,
																&success);
		if (success) {
			if (structured.code > 0 && structured.code < EndEnumCode) {
				if (!structured.data || (structured.data && structured.data[structured.dataLength-1] == '\0')) {
					messageHandlers[structured.code](aHandler, structured,
													 conv, who, modified_input_msg);
					return TRUE;
				} else {
					// Data is not a string, thus it's not a JBL message
					*modified_input_msg = g_strdup(original_msg);
					return FALSE;
				}
			} else {
				*modified_input_msg = g_strdup(original_msg);
				return FALSE;
			}
		} else {
			*modified_input_msg = g_strdup(original_msg);
			return FALSE;
		}
	}
	
	return FALSE;
}

gboolean ProtocolHandlerHandleOutput(ProtocolHandlerRef aHandler,
                                     PurpleConnection *gc,
                                     const char *who,
                                     const char *original_msg,
                                     char **modified_output_msg)
{
	assert(aHandler != NULL);
	assert(gc != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(original_msg != NULL);
	assert(strlen(original_msg) > 0);
	assert(modified_output_msg != NULL);
	
	//puts(__FUNCTION__);
	
	gboolean modified = FALSE;
	
	if (strcmp(original_msg, ":encrypt=1") == 0) {
		ProtocolHandlerEnable(aHandler, gc, who, original_msg, modified_output_msg);
		modified = TRUE;
		*modified_output_msg = NULL;
	} else if (strcmp(original_msg, ":encrypt=0") == 0) {
		ProtocolHandlerDisable(aHandler);
		modified = TRUE;
		*modified_output_msg = NULL;
	} else if (aHandler->encryption_enabled == TRUE) {
		assert(aHandler->symCipher != NULL);
		
		unsigned int outputLength = 0;
		void *encrypted = SymCipherEncrypt(aHandler->symCipher, original_msg,
										   strlen(original_msg)+1, &outputLength);
		assert(encrypted != NULL);
		assert(outputLength > 0);
		
		char *b64Data = purple_base64_encode(encrypted, outputLength);
		assert(b64Data != NULL);
		printf("B64:%s\n", b64Data);
		
		StructuredMessage structured = {EncryptedUserMessageCode, b64Data, strlen(b64Data)+1};
		*modified_output_msg = StructuredMessagePack(structured);
		g_free(encrypted);
		g_free(b64Data);
		modified = TRUE;
	}
	
	return modified;
}


#pragma mark Protocol private function implementations

static void ProtocolHandlerDisable(ProtocolHandlerRef aHandler)
{
	assert(aHandler != NULL);
	
	if (aHandler->encryption_enabled == FALSE &&
		aHandler->validatedStep == NotYetStartedStep)
		return;
	
	if (aHandler->peerAsymCipher) {
		AsymCipherDestroy(aHandler->peerAsymCipher);
		aHandler->peerAsymCipher = NULL;
	}
	
	if (aHandler->symCipher) {
		SymCipherDestroy(aHandler->symCipher);
		aHandler->symCipher = NULL;
	}
	
	aHandler->validatedStep = NotYetStartedStep;
	aHandler->encryption_enabled = FALSE;
}

static void ProtocolHandlerEnable(ProtocolHandlerRef aHandler,
						   PurpleConnection *gc,
						   const char *who,
						   const char *original_msg,
						   char **modified_input_msg)
{
	assert(aHandler != NULL);
	printf("%s with %s\n", __FUNCTION__, who);
	
	if (aHandler->encryption_enabled == TRUE)
		return;
	
	assert(aHandler->peerAsymCipher == NULL);
	assert(aHandler->symCipher == NULL);
	
	if (aHandler->validatedStep != NotYetStartedStep) {
		fprintf(stderr, "JBL Error: trying to initiate JBL protocol but it has already been started\n");
		return;
	}
	
	// Now we miss the peer's pub key and a secret key, initiate
	// the JBL protocol
	
	PurpleConversation *conv = purple_find_conversation_with_account
	(PURPLE_CONV_TYPE_IM, who, gc->account);
	
	if (!conv) {
		fprintf(stderr, "ProtocolHandlerHandleInput: Could not find conv for %s\n",
				who);
		return;
	}
	
	// Step 2
	purple_conv_im_send(PURPLE_CONV_IM(conv), LetsEnableEncryptionRequestString);
	aHandler->validatedStep = LetsEnableEncryptionRequestStep;
	
	// End of it for now
}


#pragma mark Message handlers
static void BadMessageHandler(ProtocolHandlerRef aHandler,
							  StructuredMessage structured,
							  PurpleConversation *conv,
							  const char *who,
							  char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(!structured.data ||
		   (structured.data && structured.data[structured.dataLength-1] == '\0'));
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	printf("%s with %s\n", __FUNCTION__, who);
	
	fprintf(stderr, "BadMessageHandler\n");
	assert(FALSE);
}

static void StopEncryptionHandler(ProtocolHandlerRef aHandler,
								  StructuredMessage structured,
								  PurpleConversation *conv,
								  const char *who,
								  char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(!structured.data ||
		   (structured.data && structured.data[structured.dataLength-1] == '\0'));
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	printf("%s with %s\n", __FUNCTION__, who);
	
	ProtocolHandlerDisable(aHandler);
	*modified_input_msg = NULL;
	aHandler->validatedStep = NotYetStartedStep;
}

static void PublicKeyRequestHandler(ProtocolHandlerRef aHandler,
									StructuredMessage yourStructured,
									PurpleConversation *conv,
									const char *who,
									char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(!yourStructured.data ||
		   (yourStructured.data &&
			yourStructured.data[yourStructured.dataLength-1] == '\0'));
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	printf("%s with %s\n", __FUNCTION__, who);
	
	// Gather our pub key
	const char *hexPub = AsymCipherGetPublicKey(aHandler->localAsymCipher);
	unsigned hexPubLength = strlen(hexPub) + 1;
	
	// Serialize message
	StructuredMessage structured = {PublicKeyMessageCode, hexPub, hexPubLength};
	StructuredMessageSend(structured, conv);
	
	// Clean
	*modified_input_msg = NULL;
	aHandler->validatedStep = MyPublicKeyMessageStep;
}

static void PublicKeyMessageHandler(ProtocolHandlerRef aHandler,
									StructuredMessage structured,
									PurpleConversation *conv,
									const char *who,
									char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(!structured.data ||
		   (structured.data && structured.data[structured.dataLength-1] == '\0'));
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	printf("%s with %s\n", __FUNCTION__, who);
	
	// If he sends a pub key and we didn't ask for one
	if (aHandler->validatedStep != ItsPublicKeyRequestStep) {
		// Serialize message
		StructuredMessage structured =
		{PublicKeyAnswerCode, NOKString, strlen(NOKString)+1};
		StructuredMessageSend(structured, conv);
	} else { // ItsPublicKeyRequestStep
		// Get the key
		assert(aHandler->peerAsymCipher == NULL);
		aHandler->peerAsymCipher = AsymCipherCreateWithPublicKey(structured.data);
		assert(aHandler->peerAsymCipher != NULL);
		
		// Serialize message
		StructuredMessage structured =
		{PublicKeyAnswerCode, OKString, strlen(OKString)+1};
		StructuredMessageSend(structured, conv);
	}
	
	*modified_input_msg = NULL;
	aHandler->validatedStep = ItsPublicKeyAnswerStep;
}

static void PublicKeyAnswerHandler(ProtocolHandlerRef aHandler,
								   StructuredMessage structured,
								   PurpleConversation *conv,
								   const char *who,
								   char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(!structured.data ||
		   (structured.data && structured.data[structured.dataLength-1] == '\0'));
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	printf("%s with %s\n", __FUNCTION__, who);
	
	if (aHandler->validatedStep == MyPublicKeyMessageStep) {
		if (strcmp(structured.data, OKString) == 0) {
			assert(aHandler->localAsymCipher != NULL);
			
			// The peer has our pub key but we don't have its
			if (aHandler->peerAsymCipher == NULL) {
				// Skip step 8 (assume we never know the public key)
				// Do step 9
				StructuredMessage msg = {PublicKeyRequestCode, NULL, 0};
				StructuredMessageSend(msg, conv);
				aHandler->validatedStep = ItsPublicKeyRequestStep;
				*modified_input_msg = NULL;
			} else {
				assert(aHandler->peerAsymCipher != NULL);
				
				// Now create secret key
				aHandler->symCipher = SymCipherCreateWithGeneratedKey();
				assert(aHandler->symCipher != NULL);
				
				char *secretKeyHex = SymCipherGetKey(aHandler->symCipher);
				char *saltHex = SymCipherGetSalt(aHandler->symCipher);
				assert(secretKeyHex != NULL);
				assert(saltHex);
				
				unsigned long secretKeyLength = 0;
				char *secretKey = (char *)purple_base16_decode(secretKeyHex,
															   &secretKeyLength);
				assert(secretKey != NULL);
				assert(secretKeyLength == SYMCIPHER_KEY_LENGTH);
				
				unsigned long saltLength = 0;
				char *salt = (char *)purple_base16_decode(saltHex, &saltLength);
				assert(salt != NULL);
				assert(saltLength == SYMCIPHER_SALT_LENGTH);
				
				char keyPlusSalt[SYMCIPHER_KEY_LENGTH + SYMCIPHER_SALT_LENGTH];
				memcpy(keyPlusSalt, secretKey, SYMCIPHER_KEY_LENGTH);
				memcpy(keyPlusSalt + SYMCIPHER_KEY_LENGTH, salt,
					   SYMCIPHER_SALT_LENGTH);
				
				unsigned long encryptedSecretLength = 0;
				void *encryptedSecret = AsymCipherEncrypt(aHandler->peerAsymCipher,
														  keyPlusSalt,
														  SYMCIPHER_KEY_LENGTH +
														  SYMCIPHER_SALT_LENGTH,
														  &encryptedSecretLength);
				
				char *encryptedSecretHex = purple_base16_encode(encryptedSecret,
																encryptedSecretLength);
				
				// Serialize and send the secret key
				StructuredMessage structured =
				{SecretKeyTransmissionCode, encryptedSecretHex, strlen(encryptedSecretHex)+1};
				StructuredMessageSend(structured, conv);
				
				g_free(encryptedSecret);
				g_free(encryptedSecretHex);
				
				*modified_input_msg = NULL;
				aHandler->validatedStep = SecretKeyTransmissionStep;
			}
		} else if (strcmp(structured.data, NOKString) == 0) {
			// Peer refused my public key, abort protocol
			ProtocolHandlerDisable(aHandler);
			*modified_input_msg = NULL;
			aHandler->validatedStep = NotYetStartedStep;
		} else {
			fprintf(stderr, "PublicKeyAnswerHandler: malformed data: %s found"
					" but %s or %s expected\n",
					structured.data, OKString, NOKString);
			*modified_input_msg = NULL;
		}
		
	} else {
		fprintf(stderr, "PublicKeyAnswerHandler error: got public key answer but"
				" I did not send any public key request\n");
		*modified_input_msg = NULL;
	}
}


static void PublicKeyAlreadyKnownHandler(ProtocolHandlerRef aHandler,
										 StructuredMessage structured,
										 PurpleConversation *conv,
										 const char *who,
										 char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(!structured.data ||
		   (structured.data && structured.data[structured.dataLength-1] == '\0'));
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	printf("%s with %s\n", __FUNCTION__, who);
	
	assert(NULL == "Not implemented yet");
}

static void SecretKeyTransmissionHandler(ProtocolHandlerRef aHandler,
									StructuredMessage structured,
									PurpleConversation *conv,
									const char *who,
									char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(!structured.data ||
		   (structured.data && structured.data[structured.dataLength-1] == '\0'));
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	printf("%s with %s\n", __FUNCTION__, who);
	
	/*if (aHandler->validatedStep == ItsPublicKeyAnswerStep) {*/
	if (aHandler->localAsymCipher != NULL && aHandler->peerAsymCipher != NULL) {
		assert(aHandler->localAsymCipher != NULL);
		
		const char *encryptedSecretKeyHex = structured.data;
		
		// Hex to encrypted bin
		unsigned long encryptedSecretKeyLength = 0;
		unsigned char *encryptedSecretKey =
		purple_base16_decode(encryptedSecretKeyHex,
							 &encryptedSecretKeyLength);
		assert(encryptedSecretKey != NULL && encryptedSecretKeyLength > 0);
		
		// Encrypted bin to bin
		unsigned long keyPlusSaltLength = 0;
		char *keyPlusSalt = AsymCipherDecrypt(aHandler->localAsymCipher,
											encryptedSecretKey,
											encryptedSecretKeyLength,
											&keyPlusSaltLength);
		
		assert(keyPlusSalt != NULL &&
			   keyPlusSaltLength == SYMCIPHER_KEY_LENGTH + SYMCIPHER_SALT_LENGTH);
		
		// Decomposition
		unsigned char secretKey[SYMCIPHER_KEY_LENGTH];
		unsigned char salt[SYMCIPHER_SALT_LENGTH];
		memcpy(secretKey, keyPlusSalt, SYMCIPHER_KEY_LENGTH);
		memcpy(salt, keyPlusSalt+SYMCIPHER_KEY_LENGTH, SYMCIPHER_SALT_LENGTH);
		
		// Encode
		char *secretKeyHex = purple_base16_encode(secretKey, SYMCIPHER_KEY_LENGTH);
		char *saltHex = purple_base16_encode(salt, SYMCIPHER_SALT_LENGTH);
		
		// Create symetric cipher
		aHandler->symCipher = SymCipherCreateWithKey(secretKeyHex,
													 saltHex);
		assert(aHandler->symCipher != NULL);
		
		// Clean
		g_free(encryptedSecretKey);
		g_free(keyPlusSalt);
		g_free(secretKeyHex);
		g_free(saltHex);
		
		// Notify the peer that the secret key reception and decryption went well
		StructuredMessage structured =
		{SecretKeyAnswerCode, OKString, strlen(OKString)+1};
		StructuredMessageSend(structured, conv);
		
		aHandler->validatedStep = EncryptionIsEnabledStep;
		aHandler->encryption_enabled = TRUE;
		*modified_input_msg = NULL;
	} else {
		fprintf(stderr, "SecretKeyTransmissionHandler: protocol error: the peer does"
				" not know my public key yet but it sent me a secret key (step %d)\n",
				aHandler->validatedStep);
		*modified_input_msg = NULL;
	}
}

static void SecretKeyAnswerHandler(ProtocolHandlerRef aHandler,
								   StructuredMessage structured,
								   PurpleConversation *conv,
								   const char *who,
								   char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(!structured.data ||
		   (structured.data && structured.data[structured.dataLength-1] == '\0'));
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	printf("%s with %s\n", __FUNCTION__, who);
	
	if (aHandler->validatedStep == SecretKeyTransmissionStep) {
		if (strcmp(structured.data, OKString) == 0) {
			// Finalize encryption enabling
			aHandler->validatedStep = EncryptionIsEnabledStep;
			aHandler->encryption_enabled = TRUE;
			*modified_input_msg = NULL;
		} else if (strcmp(structured.data, NOKString) == 0) {
			// Error with secret key, abort protocol
			ProtocolHandlerDisable(aHandler);
			*modified_input_msg = NULL;
			aHandler->validatedStep = NotYetStartedStep;
		} else {
			fprintf(stderr, "SecretKeyAnswerHandler: malformed data: %s found"
					" but %s or %s expected\n",
					structured.data, OKString, NOKString);
			*modified_input_msg = NULL;
		}
	} else {
		fprintf(stderr, "SecretKeyAnswerHandler: protocol error: the peer does"
				" not know the secret key yet but it sent me a secret key answer\n");
		*modified_input_msg = NULL;
	}
}

static void EncryptedUserMessageHandler(ProtocolHandlerRef aHandler,
										StructuredMessage structured,
										PurpleConversation *conv,
										const char *who,
										char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(!structured.data ||
		   (structured.data && structured.data[structured.dataLength-1] == '\0'));
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	printf("%s with %s\n", __FUNCTION__, who);
	
	if (aHandler->validatedStep == EncryptionIsEnabledStep) {
		assert(aHandler->symCipher != NULL);
		
		const char *b64Encrypted = structured.data;
		printf("B64:%s\n", b64Encrypted);
		
		unsigned long encryptedLength = 0;
		unsigned char *encrypted = purple_base64_decode(b64Encrypted, &encryptedLength);
		assert(encrypted != NULL);
		assert(encryptedLength > 0);
		
		unsigned int messageLength;
		char *message = SymCipherDecrypt(aHandler->symCipher,
										 encrypted,
										 encryptedLength,
										 &messageLength);
		
		assert(message && messageLength > 0);
		*modified_input_msg = message;
		printf("Decrypte: %s\n", message);
		g_free(encrypted);
	} else {
		fprintf(stderr, "EncryptedUserMessageHandler: protocol error: received"
				" encrypted user message but encryption is not ready\n");
		*modified_input_msg = structured.data;
	}
}


