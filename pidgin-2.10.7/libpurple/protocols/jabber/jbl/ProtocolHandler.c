
#include "../../../connection.h"
#include "ProtocolHandler.h"
#include "AsymCipher.h"
#include "SymCipher.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <glib.h>


#pragma mark RawMessage

typedef struct {
	unsigned char code;
	const void *data;
	unsigned int dataLength;
} RawMessage;

static unsigned char *RawMessagePack(RawMessage message)
{
	void *finalBuffer = g_malloc(message.dataLength + 1);
	
	// Append objects
	memcpy(finalBuffer, &message.code, 1);
	
	if (message.dataLength > 0)
		memcpy(finalBuffer + 1, message.data, message.dataLength);
	
	return purple_base64_encode(finalBuffer, message.dataLength + 1);
}

static RawMessage RawMessageExtract(const unsigned char *b64Data)
{
	assert(b64Data != NULL);
	RawMessage message = {0, NULL, 0};
	
	gsize decodedLength = 0;
	guchar *decoded = purple_base64_decode(b64Data, &decodedLength);
	
	assert(decodedLength > 0);
	memcpy(&message.code, decoded, 1);
	
	if (decodedLength > 1) {
		message.data = g_malloc(decodedLength-1);
		memcpy(message.data, decoded + 1, decodedLength-1);
		message.dataLength = decodedLength-1;
	}
	
	return message;
}

typedef enum {
	AbortCode = 1
} ProtocolCode;

static void RawMessageDestroy(RawMessage message)
{
	if (message.data) g_free(message.data);
}


#pragma mark
#pragma mark Protocol handler
#pragma mark

#pragma mark Protocol private function declarations
static void ProtocolHandlerDisable(ProtocolHandlerRef aHandler);
static void ProtocolHandlerEnable(ProtocolHandlerRef,
								  PurpleConnection *gc,
								  const char *who,
								  char *original_msg,
								  char **modified_input_msg);

#pragma mark Protocol steps

typedef enum {
	NotYetStartedStep = 0,
	LetsEnableEncryptionRequestStep = 2,
	LetsEnableEncryptionAnswerStep = 3, // after this step, use raw messages
	ItsPublicKeyIsKnownStep = 4,
	ItsPublicKeyRequestStep = 5,
	ItsPublicKeyAnswerStep = 6,
	MyPublicKeyIsKnownStep = 7,
	MyPublicKeyRequestStep = 8,
	MyPublicKeyAnswerStep = 9,
	CreateSecretStep = 10,
	SecretKeySendingStep = 11,
	SecretKeyAnswerStep = 12,
	EncryptionIsEnabledStep = 13
} ProtocolStep;


#pragma mark Protocol strings

static const char *LetsEnableEncryptionRequestString = ":lets-enable-encryption";
static const char *LetsEnableEncryptionOkAnswerString = ":ok-lets-encrypt";
static const char *LetsEnableEncryptionNokAnswerString = ":no-i-dont-want-to";


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
                                    char *original_msg,
                                    char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(gc != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(original_msg != NULL);
	assert(strlen(original_msg) > 0);
	assert(modified_input_msg != NULL);
	
	PurpleConversation *conv = purple_find_conversation_with_account
	(PURPLE_CONV_TYPE_IM, who, gc->account);
	
	if (!conv) {
		fprintf("ProtocolHandlerHandleInput: Could not find conv for %s\n",
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
			*modified_input_msg = NULL;
			aHandler->validatedStep = LetsEnableEncryptionAnswerStep;
			
			// Skip step 4 (assume we never know the public key)
			// Do step 5
			RawMessage msg = {};
		}
	}
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
	
	gboolean modified = FALSE;
	
	if (strcmp(original_msg, ":encrypt=1") == 0) {
		ProtocolHandlerEnable(aHandler, gc, who, original_msg, modified_output_msg);
		modified = TRUE;
		*modified_output_msg = NULL;
		
		
	} else if (strcmp(original_msg, ":encrypt=0") == 0) {
		ProtocolHandlerDisable(aHandler);
		modified = TRUE;
		*modified_output_msg = NULL;
	}
	
	return modified;
}


#pragma mark Protocol private function implementations

static void ProtocolHandlerDisable(ProtocolHandlerRef aHandler)
{
	assert(aHandler != NULL);
	
	if (aHandler->encryption_enabled == FALSE)
		return;
	
	if (aHandler->peerAsymCipher) {
		AsymCipherDestroy(aHandler->peerAsymCipher);
		aHandler->peerAsymCipher = NULL;
	}
	
	if (aHandler->symCipher) {
		SymCipherDestroy(aHandler->symCipher);
		aHandler->symCipher = NULL;
	}
	
	aHandler->encryption_enabled = FALSE;
}

static gboolean ProtocolHandlerEnable(ProtocolHandlerRef,
						   PurpleConnection *gc,
						   const char *who,
						   char *original_msg,
						   char **modified_input_msg)
{
	assert(aHandler != NULL);
	
	if (aHandler->encryption_enabled == TRUE)
		return TRUE;
	
	assert(aHandler->peerAsymCipher == NULL);
	assert(aHandler->symCipher == NULL);
	gboolean success = FALSE;
	
	if (aHandler->validatedStep != NotYetStartedStep) {
		fprint(stderr, "JBL Error: trying to initiate JBL protocol but it has already been started\n");
		return FALSE;
	}
	
	// Now we miss the peer's pub key and a secret key, initiate
	// the JBL protocol
	
	PurpleConversation *conv = purple_find_conversation_with_account
	(PURPLE_CONV_TYPE_IM, who, gc->account);
	
	if (!conv)
		return FALSE;
	
	// Step 2
	purple_conv_im_send(PURPLE_CONV_IM(conv), LetsEnableEncryptionRequestString);
	aHandler->validatedStep = LetsEnableEncryptionRequestStep;
	
	// End of it for now
}

