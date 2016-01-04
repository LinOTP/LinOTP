/*
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
 *
 *   This file is part of LinOTP admin clients.
 *
 *   This program is free software: you can redistribute it and/or
 *   modify it under the terms of the GNU Affero General Public
 *   License, version 3, as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the
 *              GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *    E-mail: linotp@lsexperts.de
 *    Contact: www.linotp.org
 *    Support: www.lsexperts.de
 *
 */
 
#include "liblinotpetwrapper.h"

int showme(const char *path, int type)
{

	printf ("%s", path);
	printf ("%i", type);
        return 1;
} 

int printme()
{
	printf("Hallo \n \n");
	printf("Das hier wird in der shared library geschrieben...\n");
	return 1;
}

CK_RV my_OTP_Create(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen, CK_ULONG dduration)
{
  CK_ULONG mech = CK_SAPI_OTP_HMAC_SHA1_DEC6;
  CK_BBOOL ck_false = FALSE;
  CK_ATTRIBUTE tCreate[]= {
	{CKA_SAPI_OTP_MECHANISM,    &mech,        sizeof(CK_ULONG)},
  	{CKA_SAPI_OTP_VALUE,        RandomData,   ulRandomLen    },
	{CKA_SAPI_OTP_DURATION,	    &dduration,		sizeof(CK_ULONG)},	
	{CKA_SAPI_OTP_NEXT_ALLOWED, &ck_false,     sizeof(CK_BBOOL)},
  };
  return SAPI_OTP_Create(hSession, tCreate, sizeof(tCreate)/sizeof(CK_ATTRIBUTE));
}

CK_RV  my_GetTokenSerial( CK_SLOT_ID slotId, char ** serial)
{
   CK_TOKEN_INFO token_info;
   CK_RV rv = C_GetTokenInfo( slotId, &token_info );
   CK_CHAR_PTR  sn;
   sn = token_info.serialNumber;
  
   //printf("Eingang: %s\n", *serial );
   int i;
   char s1[20]="1234567890123456789\000";
   char s2[20]="1234567890123456789\000";
 
   for ( i=0; i<16; i++)
   {
   //  printf ("Processing %d .", i);
   //  printf ("Processing %d .", i);
     sprintf (s1, "%d\t %c", sn[i], sn[i]);
     if ( sn[i] == 32 ) {
	     //printf(" found the end\n");
	     s2[i]=0;
     }else{
	     s2[i]=sn[i];
     }
     //printf ("Processing %d .", i);
     //printf ("\tcharakter : %s\n", s1);
     //printf ("\n[%s]\n", s2);
   }
   s2[19]='\000'; 
   *serial = s2;
   //printf("%s|\n",*serial);
  return rv;
}
//CK_CHAR       serialNumber[16];    /* blank padded */
