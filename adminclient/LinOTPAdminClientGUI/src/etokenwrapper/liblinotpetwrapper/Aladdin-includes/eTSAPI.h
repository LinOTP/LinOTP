/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                                         *
 *   Copyright 2008 - 2009 by Aladdin Knowledge Systems Ltd. Tel Aviv, Israel              *
 *                                                                                         *
 *   All Rights Reserved                                                                   *
 *                                                                                         *
 *   Permission to use, copy, modify and distribute this                                   *
 *   software and its documentation for any purpose is                                     *
 *   restricted according to the software end user license                                 *
 *   attached to this software.                                                            *
 *                                                                                         *
 *   Any use of this software is subject to the limitations                                *
 *   of warranty and liability contained in the end user                                   *
 *   license.  Without derogating from the abovesaid,                                      *
 *   Aladdin Knowledge SystemsLtd. disclaims all warranty with                             *
 *   regard to this software, including all implied warranties of                          *
 *   merchantability and fitness.  In no event shall Aladdin                               *
 *   Knowledge SystemsLtd. be held liable for any special, indirect                        *
 *   or consequential damages or any damages whatsoever                                    *
 *   resulting from loss of use, data or profits, whether in                               *
 *   an action of contract, negligence or other tortious                                   *
 *   action, arising out of or in connection with the use or                               *
 *   performance of this software.                                                         *
 *                                                                                         *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#include "pkcs11.h"

#ifndef _ETOKEN_SAPI_INCLUDDED_
#define _ETOKEN_SAPI_INCLUDDED_

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------- Slot attributes -------------
#define CKA_SAPI_SLOT_TYPE                   0x80001001
#define CKA_SAPI_SLOT_NAME                   0x80001002

// --------------------- Token attributes -------------
#define CKA_SAPI_PRODUCT_NAME                0x80001101
#define CKA_SAPI_MODEL                       0x80001102
#define CKA_SAPI_FW_VERSION                  0x80001103
#define CKA_SAPI_FW_REVISION                 0x80001104
#define CKA_SAPI_HW_VERSION                  0x80001105
#define CKA_SAPI_HW_INTERNAL                 0x80001106
#define CKA_SAPI_PRODUCTION_DATE             0x80001107
#define CKA_SAPI_CASE_MODEL                  0x80001108
#define CKA_SAPI_TOKEN_ID                    0x80001109
#define CKA_SAPI_CARD_ID                     0x8000110a
#define CKA_SAPI_CARD_TYPE                   0x8000110b
#define CKA_SAPI_CARD_VERSION                0x8000110c
#define CKA_SAPI_SERIAL                      0x8000110d
#define CKA_SAPI_COLOR                       0x8000110e
#define CKA_SAPI_RSA_KEYS                    0x8000110f
#define CKA_SAPI_RETRY_USER                  0x80001110
#define CKA_SAPI_RETRY_SO                    0x80001111
#define CKA_SAPI_RETRY_USER_MAX              0x80001112
#define CKA_SAPI_RETRY_SO_MAX                0x80001113
#define CKA_SAPI_PIN_USER                    0x80001114
#define CKA_SAPI_PIN_SO                      0x80001115
#define CKA_SAPI_PIN_CURRENT                 0x80001116
#define CKA_SAPI_OLD_KEY                     0x80001117
#define CKA_SAPI_NEW_KEY                     0x80001118
#define CKA_SAPI_USER_PIN_INITIALIZED        0x80001119
#define CKA_SAPI_HAS_BATTERY                 0x8000111a
#define CKA_SAPI_HAS_LCD                     0x8000111b
#define CKA_SAPI_HAS_USER                    0x8000111c
#define CKA_SAPI_HAS_SO                      0x8000111d
#define CKA_SAPI_FIPS                        0x8000111e
#define CKA_SAPI_FIPS_SUPPORTED              0x8000111f
#define CKA_SAPI_INIT_PIN_REQ                0x80001120
#define CKA_SAPI_RSA_2048                    0x80001121
#define CKA_SAPI_RSA_2048_SUPPORTED          0x80001122
#define CKA_SAPI_HMAC_SHA1                   0x80001123
#define CKA_SAPI_HMAC_SHA1_SUPPORTED         0x80001124
#define CKA_SAPI_REAL_COLOR                  0x80001125
#define CKA_SAPI_MAY_INIT                    0x80001126
#define CKA_SAPI_MASS_STORAGE_PRESENT        0x80001127
#define CKA_SAPI_MASS_STORAGE_SECURED        0x80001130

// ------------------- Battery attributes -------------
#define CKA_SAPI_BI_REPLACEABLE              0x80001201
#define CKA_SAPI_BI_HW_MEASURING             0x80001202
#define CKA_SAPI_BI_CAPACITY                 0x80001203
#define CKA_SAPI_BI_VALUE                    0x80001204
#define CKA_SAPI_BI_FIRST_WARN               0x80001205
#define CKA_SAPI_BI_SECOND_WARN              0x80001206
#define CKA_SAPI_BI_ASSEMBLY_DATE            0x80001207
#define CKA_SAPI_BI_RECALIBRATION_DATE       0x80001208
#define CKA_SAPI_BI_CONFIG                   0x80001209
#define CKA_SAPI_BI_HW_VALUE                 0x8000120a
#define CKA_SAPI_BI_HW_WARN1                 0x8000120b
#define CKA_SAPI_BI_HW_WARN2                 0x8000120c
#define CKA_SAPI_BI_HW_WARN3                 0x8000120d

// ----------------------- OTP attributes -------------
#define CKA_SAPI_OTP_MECHANISM               0x80001301
#define CKA_SAPI_OTP_COUNTER                 0x80001302
#define CKA_SAPI_OTP_DURATION                0x80001303
#define CKA_SAPI_OTP_VALUE                   0x80001304
#define CKA_SAPI_OTP_CURRENT_ALLOWED         0x80001305
#define CKA_SAPI_OTP_NEXT_ALLOWED            0x80001306
#define CKA_SAPI_OTP_ZERO_ALLOWED            0x80001307
#define CKA_SAPI_OTP_CUSTOM_DURATION_ALLOWED 0x80001308

// ----------------------- Slot types -----------------
#define CK_SAPI_SLOT_SC_VIRTUAL              0x00000001
#define CK_SAPI_SLOT_SC_READER               0x00000002
#define CK_SAPI_SLOT_FILE                    0x00000003

// --------------- Smartcard types --------------------
#define CK_SAPI_CARD_NONE                    0x00000000
#define CK_SAPI_CARD_OS                      0x00000001

// ---------------- OTP mechanism ---------------------
#define CK_SAPI_OTP_HMAC_SHA1_DEC6           0x00000001

// -------------------- OTP modes ---------------------
#define CK_SAPI_OTP_NEXT                     0x00000000
#define CK_SAPI_OTP_CURRENT                  0x00000001
#define CK_SAPI_OTP_ZERO                     0x00000002
#define CK_SAPI_OTP_RELEASE                  0x00000081

// --------------- OTP mechanism flags ----------------
#define CK_SAPI_OTP_CURRENT_SUPPORTED        0x00000001
#define CK_SAPI_OTP_NEXT_SUPPORTED           0x00000002
#define CK_SAPI_OTP_ZERO_SUPPORTED           0x00000004
#define CK_SAPI_OTP_CUSTOM_DURATION          0x00000008
#define CK_SAPI_OTP_CTL_NEXT                 0x00000010
#define CK_SAPI_OTP_CTL_DURATION             0x00000020
#define CK_SAPI_OTP_BUTTON_SUPPORTED         0x00000040

// ------------------ Token colors --------------------
#define CK_SAPI_COLOR_RED                    0x00000000
#define CK_SAPI_COLOR_BLUE                   0x00000001
#define CK_SAPI_COLOR_GREEN                  0x00000002
#define CK_SAPI_COLOR_TANGERINE              0x00000003
#define CK_SAPI_COLOR_ICE                    0x00000004
#define CK_SAPI_COLOR_PURPLE                 0x00000005
#define CK_SAPI_COLOR_LIME                   0x00000006
#define CK_SAPI_COLOR_PINK                   0x00000007
#define CK_SAPI_COLOR_BLACK                  0x00000008

// ------------------ Token cases ---------------------
#define CK_SAPI_CASE_NONE                    0x00000000
#define CK_SAPI_CASE_CLASSIC                 0x00000001
#define CK_SAPI_CASE_NG1                     0x00000002
#define CK_SAPI_CASE_NG2                     0x00000003
#define CK_SAPI_CASE_NG2_NOLCD               0x00000004

// ------------------ Error codes ---------------------
#define CKR_SAPI_OBJECT_DOES_NOT_EXIST       0x80000101
#define CKR_SAPI_OBJECT_ALREADY_EXISTS       0x80000102
#define CKR_SAPI_NOT_SUPPORTED_BY_TOKEN      0x80000103
#define CKR_SAPI_PIN_QUALITY                 0x80000201
#define CKR_SAPI_PIN_DEFAULT                 0x80000202
#define CKR_SAPI_PIN_EXPIRATION              0x80000203
#define CKR_SAPI_PIN_CHANGE_NOT_ALLOWED      0x80000204
#define CKR_SAPI_CANCELLED                   0x80000301

#ifndef ETOKENEXT
#if defined(_WIN32) || !defined(CRYPTOKI_EXPORTS)
#define ETOKENEXT
#else
#define ETOKENEXT __attribute__ ((visibility("default")))
#endif
#endif

// ----------------- General functions ----------------
CK_DECLARE_FUNCTION(CK_RV, SAPI_GetLibraryInfo)
( 
  CK_VERSION_PTR pSapiVersion, 
  CK_VERSION_PTR pRteVersion
);

typedef CK_RV (*f_SAPI_GetLibraryInfo)
( 
  CK_VERSION_PTR pSapiVersion, 
  CK_VERSION_PTR pRteVersion
);

CK_RV ETOKENEXT SAPI_GetSlotInfo(
  CK_SLOT_ID slotId, 
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount);

typedef CK_RV (*f_SAPI_GetSlotInfo)(
  CK_SLOT_ID slotId, 
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount);

CK_RV ETOKENEXT SAPI_GetTokenInfo(
  CK_SLOT_ID slotId, 
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount);

typedef CK_RV (*f_SAPI_GetTokenInfo)(
  CK_SLOT_ID slotId, 
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount);

CK_RV ETOKENEXT SAPI_SetTokenName(
  CK_SESSION_HANDLE hSession, 
  CK_CHAR_PTR label);

typedef CK_RV (*f_SAPI_SetTokenName)(
  CK_SESSION_HANDLE hSession, 
  CK_CHAR_PTR label);

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_INIT_CALLBACK)(CK_VOID_PTR pContext, CK_ULONG progress);

CK_RV ETOKENEXT SAPI_InitToken(
  CK_SLOT_ID slotId, 
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount, 
  CK_VOID_PTR pContext,
  CK_INIT_CALLBACK pCallback);

typedef CK_RV (*f_SAPI_InitToken)(
  CK_SLOT_ID slotId, 
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount, 
  CK_VOID_PTR pContext,
  CK_INIT_CALLBACK pCallback);

CK_RV ETOKENEXT SAPI_FindTokens(
  CK_SLOT_ID_PTR pSlots, 
  CK_ULONG_PTR pSlotCount, 
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount);

typedef CK_RV (*f_SAPI_FindTokens)(
  CK_SLOT_ID_PTR pSlots, 
  CK_ULONG_PTR pSlotCount, 
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount);

CK_RV ETOKENEXT SAPI_LocateToken(
  CK_VOID_PTR unique, 
  CK_ULONG size,
  CK_SLOT_ID_PTR pSlotId);

typedef CK_RV (*f_SAPI_LocateToken)(
  CK_VOID_PTR unique, 
  CK_ULONG size,
  CK_SLOT_ID_PTR pSlotId);

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_UNBLOCK_CALLBACK)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pChallenge, CK_VOID_PTR pResponse);
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_UNBLOCK_CALLBACK_EX)(CK_VOID_PTR pContext, CK_VOID_PTR pChallenge, CK_VOID_PTR pResponse);

CK_RV ETOKENEXT SAPI_UnblockPIN(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR pNewPin,
  CK_ULONG ulNewPinLen,
  CK_UNBLOCK_CALLBACK pCallback);

typedef CK_RV (*f_SAPI_UnblockPIN)(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR pNewPin,
  CK_ULONG ulNewPinLen,
  CK_UNBLOCK_CALLBACK pCallback);

CK_RV ETOKENEXT SAPI_UnblockPINEx(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR pNewPin,
  CK_ULONG ulNewPinLen,
  CK_UNBLOCK_CALLBACK_EX pCallback,
  CK_VOID_PTR pContext);

typedef CK_RV (*f_SAPI_UnblockPINEx)(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR pNewPin,
  CK_ULONG ulNewPinLen,
  CK_UNBLOCK_CALLBACK_EX pCallback,
  CK_VOID_PTR pContext);

//------------------- Battery --------------------
CK_RV ETOKENEXT SAPI_BI_Check(
  CK_SESSION_HANDLE hSession);

typedef CK_RV (*f_SAPI_BI_Check)(
  CK_SESSION_HANDLE hSession);

CK_RV ETOKENEXT SAPI_BI_Create(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount);

typedef CK_RV (*f_SAPI_BI_Create)(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount);

CK_RV ETOKENEXT SAPI_BI_GetAttributeValue(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount);

typedef CK_RV (*f_SAPI_BI_GetAttributeValue)(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount);

CK_RV ETOKENEXT SAPI_BI_Save(
  CK_SESSION_HANDLE hSession,
  CK_VOID_PTR pBuffer, 
  CK_ULONG_PTR pulSize);

typedef CK_RV (*f_SAPI_BI_Save)(
  CK_SESSION_HANDLE hSession,
  CK_VOID_PTR pBuffer, 
  CK_ULONG_PTR pulSize);

CK_RV ETOKENEXT SAPI_BI_Restore(
  CK_SESSION_HANDLE hSession,
  CK_VOID_PTR pBuffer, 
  CK_ULONG size);

typedef CK_RV (*f_SAPI_BI_Restore)(
  CK_SESSION_HANDLE hSession,
  CK_VOID_PTR pBuffer, 
  CK_ULONG size);

CK_RV ETOKENEXT SAPI_BI_SetAttributeValue(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount);

typedef CK_RV (*f_SAPI_BI_SetAttributeValue)(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount);

CK_RV ETOKENEXT SAPI_BI_Destroy(
  CK_SESSION_HANDLE hSession);

typedef CK_RV (*f_SAPI_BI_Destroy)(
  CK_SESSION_HANDLE hSession);

CK_RV ETOKENEXT SAPI_BI_Recalibrate(
  CK_SESSION_HANDLE hSession, 
  CK_DATE* pCurrentDate);

typedef CK_RV (*f_SAPI_BI_Recalibrate)(
  CK_SESSION_HANDLE hSession, 
  CK_DATE* pCurrentDate);

CK_RV ETOKENEXT SAPI_BI_GetConfig(
  CK_CHAR_PTR  pInf,
  CK_ULONG     ulInfLen,
  CK_CHAR_PTR  pModel,
  CK_ULONG_PTR pCapacity,
  CK_VOID_PTR  pConfig,
  CK_ULONG_PTR pulConfigLen);

typedef CK_RV (*f_SAPI_BI_GetConfig)(
  CK_CHAR_PTR  pInf,
  CK_ULONG     ulInfLen,
  CK_CHAR_PTR  pModel,
  CK_ULONG_PTR pCapacity,
  CK_VOID_PTR  pConfig,
  CK_ULONG_PTR pulConfigLen);

// ----------------------- OTP -------------------

typedef struct tagCK_SAPI_OTP_MECHANISM_INFO
{
  CK_ULONG       mechanism;                      // CK_SAPI_OTP_HMAC_SHA1_DEC6
  CK_ULONG       minKeyLen;
  CK_ULONG       maxKeyLen;
  CK_ULONG       OTPLen;                         // 6
  CK_ULONG       defDuration;
  CK_ULONG       flags;
} CK_SAPI_OTP_MECHANISM_INFO, *CK_SAPI_OTP_MECHANISM_INFO_PTR;

CK_RV ETOKENEXT SAPI_OTP_GetMechanismList(
  CK_SLOT_ID slotId, 
  CK_ULONG_PTR pMechanismList, 
  CK_ULONG_PTR pCount);

typedef CK_RV (*f_SAPI_OTP_GetMechanismList)(
  CK_SLOT_ID slotId, 
  CK_ULONG_PTR pMechanismList, 
  CK_ULONG_PTR pCount);

CK_RV ETOKENEXT SAPI_OTP_GetMechanismInfo(
  CK_SLOT_ID slotId, 
  CK_ULONG mechanism, 
  CK_SAPI_OTP_MECHANISM_INFO_PTR pMechanismInfo);

typedef CK_RV (*f_SAPI_OTP_GetMechanismInfo)(
  CK_SLOT_ID slotId, 
  CK_ULONG mechanism, 
  CK_SAPI_OTP_MECHANISM_INFO_PTR pMechanismInfo);

CK_RV ETOKENEXT SAPI_OTP_Create(
  CK_SESSION_HANDLE hSession, 
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount);

typedef CK_RV (*f_SAPI_OTP_Create)(
  CK_SESSION_HANDLE hSession, 
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount);

CK_RV ETOKENEXT SAPI_OTP_GetAttributeValue(
  CK_SESSION_HANDLE hSession, 
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount);

typedef CK_RV (*f_SAPI_OTP_GetAttributeValue)(
  CK_SESSION_HANDLE hSession, 
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount);

CK_RV ETOKENEXT SAPI_OTP_SetAttributeValue(
  CK_SESSION_HANDLE hSession, 
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount);

typedef CK_RV (*f_SAPI_OTP_SetAttributeValue)(
  CK_SESSION_HANDLE hSession, 
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount);

CK_RV ETOKENEXT SAPI_OTP_Destroy(
  CK_SESSION_HANDLE hSession);

typedef CK_RV (*f_SAPI_OTP_Destroy)(
  CK_SESSION_HANDLE hSession);

CK_RV ETOKENEXT SAPI_OTP_Execute(
  CK_SESSION_HANDLE hSession, 
  CK_ULONG mode, 
  CK_CHAR_PTR pResult, 
  CK_ULONG_PTR pSize);

typedef CK_RV (*f_SAPI_OTP_Execute)(
  CK_SESSION_HANDLE hSession, 
  CK_ULONG mode, 
  CK_CHAR_PTR pResult, 
  CK_ULONG_PTR pSize);

// -------------------- Password quality ------------
typedef struct tag_SAPI_PIN_POLICY_INFO
{
  CK_RV     warning;
  CK_ULONG  days;
  CK_ULONG  warningPeriod;
  CK_ULONG  expiryPeriod;
} SAPI_PIN_POLICY_INFO;

CK_RV ETOKENEXT SAPI_Login(
  CK_SESSION_HANDLE hSession, 
  CK_USER_TYPE userType,
  CK_CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  SAPI_PIN_POLICY_INFO* pPolicyInfo
);

typedef CK_RV (*f_SAPI_Login)(
  CK_SESSION_HANDLE hSession, 
  CK_USER_TYPE userType,
  CK_CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  SAPI_PIN_POLICY_INFO* pPolicyInfo
);

CK_RV ETOKENEXT SAPI_SetPIN(
  CK_SESSION_HANDLE hSession, 
  CK_CHAR_PTR pOldPin,
  CK_ULONG ulOldPinLen,
  CK_CHAR_PTR pNewPin,
  CK_ULONG ulNewPinLen
);

typedef CK_RV (*f_SAPI_SetPIN)(
  CK_SESSION_HANDLE hSession, 
  CK_CHAR_PTR pOldPin,
  CK_ULONG ulOldPinLen,
  CK_CHAR_PTR pNewPin,
  CK_ULONG ulNewPinLen
);

CK_RV ETOKENEXT SAPI_SetPINEx(
  CK_SESSION_HANDLE hSession, 
  CK_CHAR_PTR pNewPin,
  CK_ULONG_PTR pulNewPinLen
);

typedef CK_RV (*f_SAPI_SetPINEx)(
  CK_SESSION_HANDLE hSession, 
  CK_CHAR_PTR pNewPin,
  CK_ULONG_PTR pulNewPinLen
);

// ------------------- Server side -------------------

CK_RV ETOKENEXT SAPI_Server_BI_EstimateValue(
  CK_ATTRIBUTE_PTR pTemplate, // BI
  CK_ULONG ulCount, 
  CK_MECHANISM_TYPE mechanism,
  CK_ULONG duration,
  CK_ULONG clicks,
  CK_DATE *pCurrentDate,
  CK_ULONG_PTR pNewValue);

typedef CK_RV (*f_SAPI_Server_BI_EstimateValue)(
  CK_ATTRIBUTE_PTR pTemplate, // BI
  CK_ULONG ulCount, 
  CK_MECHANISM_TYPE mechanism,
  CK_ULONG duration,
  CK_ULONG clicks,
  CK_DATE *pCurrentDate,
  CK_ULONG_PTR pNewValue);

CK_RV ETOKENEXT SAPI_Server_BI_EstimateRetainDays(
  CK_DATE *pStartUsageDate,
  CK_ULONG StartValue,
  CK_ATTRIBUTE_PTR pTemplate, // BI
  CK_ULONG ulCount,
  CK_MECHANISM_TYPE mechanism,
  CK_ULONG duration,
  CK_ULONG clicks,
  CK_DATE *pCurrentDate,
  CK_ULONG_PTR pEstimatedDays);

typedef CK_RV (*f_SAPI_Server_BI_EstimateRetainDays)(
  CK_DATE *pStartUsageDate,
  CK_ULONG StartValue,
  CK_ATTRIBUTE_PTR pTemplate, // BI
  CK_ULONG ulCount,
  CK_MECHANISM_TYPE mechanism,
  CK_ULONG duration,
  CK_ULONG clicks,
  CK_DATE *pCurrentDate,
  CK_ULONG_PTR pEstimatedDays);

CK_RV ETOKENEXT SAPI_Server_OTP_Calculate(
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount, 
  CK_CHAR_PTR pResult, 
  CK_ULONG_PTR pSize);

typedef CK_RV (*f_SAPI_Server_OTP_Calculate)(
  CK_ATTRIBUTE_PTR pTemplate, 
  CK_ULONG ulCount, 
  CK_CHAR_PTR pResult, 
  CK_ULONG_PTR pSize);

CK_RV ETOKENEXT SAPI_Server_Unblock(
  CK_CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_VOID_PTR pChallenge, 
  CK_VOID_PTR pResponse);

typedef CK_RV (*f_SAPI_Server_Unblock)(
  CK_CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_VOID_PTR pChallenge, 
  CK_VOID_PTR pResponse);

#ifdef __cplusplus
}
#endif

#endif //_ETOKEN_SAPI_INCLUDDED_


