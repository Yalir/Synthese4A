
#ifndef PROTOCOL_HANDLER_PRIV_H
#define PROTOCOL_HANDLER_PRIV_H

#pragma mark StructuredMessage
typedef struct {
	unsigned char code;
	void *data;
	unsigned int dataLength;
} StructuredMessage;

typedef enum {
	StopEncryptionCode = 1,        // No associated data
	PublicKeyRequestCode = 2,      // No associated data
	PublicKeyMessageCode = 3,      // Public key
	PublicKeyAnswerCode = 4,       // OK or NOK
	PublicKeyAlreadyKnownCode = 5, // No associated data
	SecretKeySendingCode = 6,      // Secret key
	SecretKeyAnswerCode = 7,       // OK or NOK
	EncryptedUserMessageCode = 8,  // User message
	EndEnumCode
} ProtocolCode;

typedef void (* MessageHandler)(ProtocolHandlerRef aHandler,
								StructuredMessage structured,
								PurpleConversation *conv,
								const char *who,
								char **modified_input_msg);

#pragma mark Protocol steps

typedef enum {
	NotYetStartedStep = 0,
	LetsEnableEncryptionRequestStep = 2,
	LetsEnableEncryptionAnswerStep = 3, // after this step, use raw messages
	ItsPublicKeyIsKnownStep = 4,
	ItsPublicKeyRequestStep = 5,
	//	ItsPublicKeyMessageStep = 6,
	ItsPublicKeyAnswerStep = 7,
	MyPublicKeyIsKnownStep = 8,
	//	MyPublicKeyRequestStep = 9,
	MyPublicKeyMessageStep = 10,
	//	MyPublicKeyAnswerStep = 11,
	CreateSecretStep = 12,
	SecretKeySendingStep = 13,
	SecretKeyAnswerStep = 14,
	EncryptionIsEnabledStep = 14
} ProtocolStep;

#pragma mark Protocol strings

extern const char *LetsEnableEncryptionRequestString;
extern const char *LetsEnableEncryptionOkAnswerString;
extern const char *LetsEnableEncryptionNokAnswerString;
extern const char *NOKString;
extern const char *OKString;

#pragma mark Protocol functions

static void ProtocolHandlerDisable(ProtocolHandlerRef aHandler);
static void ProtocolHandlerEnable(ProtocolHandlerRef aHandler,
								  PurpleConnection *gc,
								  const char *who,
								  const char *original_msg,
								  char **modified_input_msg);

static void BadMessageHandler(ProtocolHandlerRef aHandler,
							  StructuredMessage structured,
							  PurpleConversation *conv,
							  const char *who,
							  char **modified_input_msg);
static void StopEncryptionHandler(ProtocolHandlerRef aHandler,
								  StructuredMessage structured,
								  PurpleConversation *conv,
								  const char *who,
								  char **modified_input_msg);
static void PublicKeyRequestHandler(ProtocolHandlerRef aHandler,
									StructuredMessage structured,
									PurpleConversation *conv,
									const char *who,
									char **modified_input_msg);
static void PublicKeyMessageHandler(ProtocolHandlerRef aHandler,
									StructuredMessage structured,
									PurpleConversation *conv,
									const char *who,
									char **modified_input_msg);
static void PublicKeyAnswerHandler(ProtocolHandlerRef aHandler,
								   StructuredMessage structured,
								   PurpleConversation *conv,
								   const char *who,
								   char **modified_input_msg);
static void PublicKeyAlreadyKnownHandler(ProtocolHandlerRef aHandler,
										 StructuredMessage structured,
										 PurpleConversation *conv,
										 const char *who,
										 char **modified_input_msg);
static void SecretKeySendingHandler(ProtocolHandlerRef aHandler,
									StructuredMessage structured,
									PurpleConversation *conv,
									const char *who,
									char **modified_input_msg);
static void SecretKeyAnswerHandler(ProtocolHandlerRef aHandler,
								   StructuredMessage structured,
								   PurpleConversation *conv,
								   const char *who,
								   char **modified_input_msg);
static void EncryptedUserMessageHandler(ProtocolHandlerRef aHandler,
										StructuredMessage structured,
										PurpleConversation *conv,
										const char *who,
										char **modified_input_msg);

#endif
