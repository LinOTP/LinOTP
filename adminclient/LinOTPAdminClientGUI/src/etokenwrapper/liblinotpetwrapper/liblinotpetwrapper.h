/*
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <wintypes.h>
#include <string.h>
#include "Aladdin-includes/eTPkcs11.h"
#include "Aladdin-includes/eTSAPI.h"



extern int printme();
extern CK_RV my_OTP_Create(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen, CK_ULONG dduration);
extern CK_RV my_GetTokenSerial( CK_SLOT_ID slotId, char ** serial);


