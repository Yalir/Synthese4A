
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
	SecretKeySendingHandler,       // 6
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
	
	gchar *encoded = purple_base64_encode(finalBuffer, message.dataLength + 1);
	g_free(finalBuffer);
	
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
		
		if (decodedLength > 1) {
			message.data = g_malloc(decodedLength-1);
			memcpy(message.data, decoded + 1, decodedLength-1);
			message.dataLength = decodedLength-1;
		}
	}
	
	g_free(decoded);
	
	return message;
}

static void StructuredMessageDestroy(StructuredMessage message)
{
	if (message.data) g_free(message.data);
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
			*modified_input_msg = NULL;
			aHandler->validatedStep = LetsEnableEncryptionAnswerStep;
			
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
				messageHandlers[structured.code](aHandler, structured,
												 conv, who, modified_input_msg);
			} else {
				*modified_input_msg = strdup(original_msg);
				return FALSE;
			}
		} else {
			*modified_input_msg = strdup(original_msg);
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
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	
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
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	
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
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	
	// Gather our pub key
	const char *hexPub = AsymCipherGetPublicKey(aHandler->localAsymCipher);
	unsigned hexPubLength = strlen(hexPub) + 1;
	
	// Serialize message
	StructuredMessage structured = {PublicKeyAnswerCode, strdup(hexPub), hexPubLength};
	char *serialized = StructuredMessagePack(structured);
	StructuredMessageDestroy(structured);
	
	// Send it
	purple_conv_im_send(PURPLE_CONV_IM(conv), serialized);
	
	// Clean
	g_free(serialized);
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
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	
	// If he sends a pub key and we didn't ask for one
	if (aHandler->validatedStep != ItsPublicKeyRequestStep) {
		// Serialize message
		StructuredMessage structured =
		{PublicKeyAnswerCode, strdup(NOKString), strlen(NOKString)+1};
		char *serialized = StructuredMessagePack(structured);
		StructuredMessageDestroy(structured);
		
		// Send it
		purple_conv_im_send(PURPLE_CONV_IM(conv), serialized);
		
		// Clean
		g_free(serialized);
	} else { // ItsPublicKeyRequestStep
		// Serialize message
		StructuredMessage structured =
		{PublicKeyAnswerCode, strdup(OKString), strlen(OKString)+1};
		char *serialized = StructuredMessagePack(structured);
		StructuredMessageDestroy(structured);
		
		// Send it
		purple_conv_im_send(PURPLE_CONV_IM(conv), serialized);
		
		// Clean
		g_free(serialized);
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
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
	
	
}

static void PublicKeyAlreadyKnownHandler(ProtocolHandlerRef aHandler,
										 StructuredMessage structured,
										 PurpleConversation *conv,
										 const char *who,
										 char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
}

static void SecretKeySendingHandler(ProtocolHandlerRef aHandler,
									StructuredMessage structured,
									PurpleConversation *conv,
									const char *who,
									char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
}

static void SecretKeyAnswerHandler(ProtocolHandlerRef aHandler,
								   StructuredMessage structured,
								   PurpleConversation *conv,
								   const char *who,
								   char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
}

static void EncryptedUserMessageHandler(ProtocolHandlerRef aHandler,
										StructuredMessage structured,
										PurpleConversation *conv,
										const char *who,
										char **modified_input_msg)
{
	assert(aHandler != NULL);
	assert(conv != NULL);
	assert(who != NULL);
	assert(strlen(who) > 0);
	assert(modified_input_msg != NULL);
}


