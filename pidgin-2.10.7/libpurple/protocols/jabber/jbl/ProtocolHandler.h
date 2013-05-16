
#ifndef PROTOCOL_HANDLER_H
#define PROTOCOL_HANDLER_H

#include <glib.h>

typedef struct ProtocolHandler_t *ProtocolHandlerRef;

/**
 * Key lengths ?
 * Signature length ?
 * Challenges + signature ?
 *
 * JBL Protocol
 *
 * Structure for raw messages:
 *
 *  1   n
 * !-!-----!
 * !c!  d  !
 * !-!-----!
 *
 * Where 'c' is the message code/type on 1 byte followed by 'd' for the remaining
 * n bytes that can contain any required data according to the message type.
 * Valid codes are:
 * - 1: public key request. No other data.
 * - 2: public key message. Data contains the public key as hexadecimal string.
 * - 3: public key answer. Data contains OK or NOK depending on public key
 * acceptation.
 * - 4: public key already known.
 * - 5: secret key transmission. Data contains the secret key encrypted with
 * the peer public key as hexadecimal string.
 * - 6: secret key answer. Data contains either OK or NOK to acknowledge for
 * secret key reception and decryption.
 * - 7: encrypted message. Data contains the encrypted message as base 64 string.
 *
 *
 * === Protocol ===
 *
 * 1. A types ":encrypt=1"
 * 2. A sends to B: ":lets-enable-encryption"
 * 3. B sends to A: ":ok-lets-encrypt" or ":no-i-dont-want-to"
 *
 * Now communication switches to raw data mode with Base64 encoding/decoding
 *
 * 4. If A already knows B's public key, A sends a public-key-already-known
 * message to B then go to step 7
 * 5. A sends a public key request to B.
 * 6. B sends its public key to A.
 * 7. A chooses whether to accept B's public key then sends a public key answer
 * to B.
 * 8. If B already knows A's public key, B sends a public-key-already-known
 * message to A then go to step 10
 * 9. B sends a public key request to A.
 * 10. A sends its public key to B.
 * 11. B chooses whether to accept A's public key then sends a public key answer
 * to A.
 * 12. A creates a secret key and sends it to B, encrypted with B's public key,
 * signed with A's private key.
 * 14. B sends a secret key answer to A, signed with B's private key
 *
 * When one user wants to stop encryption, he/she types ":encrypt=0". Then
 * ":lets-stop-encryption" is sent to the peer and the protocol is stopped.
 *
 * On failure, the communication switches back to the classical text mode.
 * On success, the messages are sent in the same raw mode with prefix code 7
 * followed by the encrypted message using the secret key and the signature of
 * the sender.
 *
 */

/** @brief Create a new JBL protocol handler
 *
 * @return an newly created and initialized JBL protocol handler
 */
ProtocolHandlerRef  ProtocolHandlerCreate(void);

/** @brief Destroy the given JBL protocol handler
 *
 * The resources and the handler will be freed
 *
 * Preconditions:
 * - aHandler must be a valid JBL protocol handler
 *
 * @param aHandler a valid JBL protocol handler to destroy
 */
void                ProtocolHandlerDestroy(ProtocolHandlerRef aHandler);

/** @brief Process a received Jabber message and eventually modify it according to 
 * @brief the JBL protocol.
 *
 * modified_input_msg should be used by the caller instead of original_msg.
 * If modified_input_msg is null after calling this function, no message
 * should be delivered to the user.
 *
 * If the original message is detected to be a JBL protocol message, it is
 * processed. This can result in either a new input message or no more input
 * message. In the later case, this means that the message was of no interest
 * for the user and was only required for JBL protocol purposes.
 *
 * Preconditions:
 * - aHandler must be a valid protocol handler
 * - gc must be a valid PurpleConnection
 * - who must be a valid string
 * - original_msg must be a valid string
 * - modified_input_msg must be a valid reference to a (non-initialized) 'char*'
 *
 * @param aHandler the JBP protocol handler to use for the input processing
 * @param gc the purple connection associated to the input message
 * @param who the sender of the message
 * @param original_msg the original received message body
 * @param modified_input_msg a reference to a non-initilized 'char*'.
 * After calling this function *modified_input_msg will either be original_msg
 * or a valid reference to a new string or null
 * @return TRUE if the original_msg hasn't been left intact (ie. modified or
 * destroyed), FALSE otherwise
 */
gboolean            ProtocolHandlerHandleInput(ProtocolHandlerRef aHandler,
                                               PurpleConnection *gc,
                                               const char *who,
                                               const char *original_msg,
                                               char **modified_input_msg);

/** @brief Process an about-to-be-sent Jabber message and eventually modify it
 * @brief according to the JBL protocol.
 *
 * modified_output_msg should be used by the caller instead of original_msg.
 * If modified_output_msg is null after calling this function, no message
 * should be sent.
 *
 * If the original message is detected to be a JBL protocol message, it is
 * processed. This can result in either a new output message or no more output
 * message. In the later case, this means that the message was of no interest
 * for the user and was only required for JBL protocol purposes.
 *
 * Preconditions:
 * - aHandler must be a valid protocol handler
 * - gc must be a valid PurpleConnection
 * - who must be a valid string
 * - original_msg must be a valid string
 * - modified_output_msg must be a valid reference to a (non-initialized)
 * 'char*'
 *
 * @param aHandler the JBP protocol handler to use for the output processing
 * @param gc the purple connection associated to the output message
 * @param who the receiver of the message
 * @param original_msg the original about-to-be-sent message body
 * @param modified_output_msg a reference to a non-initilized 'char*'.
 * After calling this function *modified_output_msg will either be original_msg
 * or a valid reference to a new string or null
 * @return TRUE if the original_msg hasn't been left intact (ie. modified or
 * destroyed), FALSE otherwise
 */
gboolean            ProtocolHandlerHandleOutput(ProtocolHandlerRef aHandler,
                                                PurpleConnection *gc,
                                                const char *who,
                                                const char *original_msg,
                                                char **modified_output_msg);

#endif // PROTOCOL_HANDLER_H
