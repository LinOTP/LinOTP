/* otp-pkcs11.h include file for the PKCS #11 Mechanisms for One-Time
   Password Tokens OTPS document. */ 
/* $Revision: 1.1 $ */

/* License to copy and use this software is granted provided that it is
 * identified as "RSA Security Inc. PKCS #11 Mechanisms for One-Time
 * Password Tokens" in all material mentioning or referencing this software.
 *
 * RSA Security Inc. makes no representations concerning either the
 * merchantability of this software or the suitability of this software for
 * any particular purpose. It is provided "as is" without express or implied
 * warranty of any kind.
 */

/* This file is preferably included after inclusion of pkcs11.h */

#ifndef _OTP_PKCS11_H_
#define _OTP_PKCS11_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

/* A.1 Object classes */
#define CKO_OTP_KEY    0x00000008

/* A.2 Key types */
#define CKK_SECURID    0x00000022
#define CKK_HOTP       0x00000023
#define CKK_ACTI       0x00000024

/* A.3 Mechanisms */
#define CKM_SECURID_KEY_GEN 0x00000280
#define CKM_SECURID         0x00000282
#define CKM_HOTP_KEY_GEN    0x00000290
#define CKM_HOTP            0x00000291
#define CKM_ACTI            0x000002A0
#define CKM_ACTI_KEY_GEN    0x000002A1

/* A.4 Attributes */
#define CKA_OTP_FORMAT                0x00000220
#define CKA_OTP_LENGTH                0x00000221
#define CKA_OTP_TIME_INTERVAL         0x00000222
#define CKA_OTP_USER_FRIENDLY_MODE    0x00000223
#define CKA_OTP_CHALLENGE_REQUIREMENT 0x00000224
#define CKA_OTP_TIME_REQUIREMENT      0x00000225
#define CKA_OTP_COUNTER_REQUIREMENT   0x00000226
#define CKA_OTP_PIN_REQUIREMENT       0x00000227
#define CKA_OTP_COUNTER               0x0000022E
#define CKA_OTP_TIME                  0x0000022F
#define CKA_OTP_USER_IDENTIFIER       0x0000022A
#define CKA_OTP_SERVICE_IDENTIFIER    0x0000022B
#define CKA_OTP_SERVICE_LOGO          0x0000022C
#define CKA_OTP_SERVICE_LOGO_TYPE     0x0000022D

/* A.5 Attribute constants */
#define CK_OTP_FORMAT_DECIMAL      0
#define CK_OTP_FORMAT_HEXADECIMAL  1
#define CK_OTP_FORMAT_ALPHANUMERIC 2
#define CK_OTP_FORMAT_BINARY       3

#define CK_OTP_PARAM_IGNORED       0
#define CK_OTP_PARAM_OPTIONAL      1
#define CK_OTP_PARAM_MANDATORY     2

/* A.6 Other constants */
#define CK_OTP_VALUE          0
#define CK_OTP_PIN            1
#define CK_OTP_CHALLENGE      2
#define CK_OTP_TIME           3
#define CK_OTP_COUNTER        4
#define CK_OTP_FLAGS          5
#define CK_OTP_OUTPUT_LENGTH  6
#define CK_OTP_OUTPUT_FORMAT  7

#define CKF_NEXT_OTP          0x00000001
#define CKF_EXCLUDE_TIME      0x00000002
#define CKF_EXCLUDE_COUNTER   0x00000004
#define CKF_EXCLUDE_CHALLENGE 0x00000008
#define CKF_EXCLUDE_PIN       0x00000010
#define CKF_USER_FRIENDLY_OTP 0x00000020

/* A.7 Notifications */
#define CKN_OTP_CHANGED       1

/* A.8 Return values */
#define CKR_NEW_PIN_MODE      0x000001B0
#define CKR_NEXT_OTP          0x000001B1

/* Structs */
typedef CK_ULONG CK_PARAM_TYPE;

typedef struct CK_OTP_PARAM {
	CK_PARAM_TYPE type;
	CK_VOID_PTR pValue;
	CK_ULONG ulValueLen;
} CK_OTP_PARAM;

typedef CK_OTP_PARAM CK_PTR CK_OTP_PARAM_PTR;

typedef struct CK_OTP_PARAMS {
	CK_OTP_PARAM_PTR pParams;
	CK_ULONG ulCount;
} CK_OTP_PARAMS;

typedef CK_OTP_PARAMS CK_PTR CK_OTP_PARAMS_PTR;

typedef struct CK_OTP_SIGNATURE_INFO {
	CK_OTP_PARAM_PTR pParams;
	CK_ULONG ulCount;
} CK_OTP_SIGNATURE_INFO;

typedef CK_OTP_SIGNATURE_INFO CK_PTR CK_OTP_SIGNATURE_INFO_PTR;

#ifdef __cplusplus
}
#endif

#endif
