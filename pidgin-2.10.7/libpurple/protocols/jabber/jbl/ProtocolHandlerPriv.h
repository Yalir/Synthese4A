
#ifndef PROTOCOL_HANDLER_PRIV_H
#define PROTOCOL_HANDLER_PRIV_H

#pragma mark StructuredMessage
typedef struct {
	unsigned char code;
	const char *data;
	unsigned int dataLength;
	gboolean sendingCommand;
} StructuredMessage;

typedef enum {
	PublicKeyRequestCode = 1,      // No associated data
	PublicKeyMessageCode = 2,      // Public key
	PublicKeyAnswerCode = 3,       // OK or NOK
	PublicKeyAlreadyKnownCode = 4, // No associated data
	SecretKeyTransmissionCode = 5, // Secret key
	SecretKeyAnswerCode = 6,       // OK or NOK
	EncryptedUserMessageCode = 7,  // User message
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
	//	CreateSecretStep = 12,
	SecretKeyTransmissionStep = 13,
	//	SecretKeyAnswerStep = 14,
	EncryptionIsEnabledStep = 15
} ProtocolStep;

#pragma mark Protocol strings

extern const char *LetsEnableEncryptionRequestString;
extern const char *LetsEnableEncryptionOkAnswerString;
extern const char *LetsEnableEncryptionNokAnswerString;
extern const char *LetsStopEncryptionString;
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
static void SecretKeyTransmissionHandler(ProtocolHandlerRef aHandler,
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
