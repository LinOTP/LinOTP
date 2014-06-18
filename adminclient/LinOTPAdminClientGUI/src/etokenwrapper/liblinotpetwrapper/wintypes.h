/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id: wintypes.h 3334 2009-03-02 14:56:38Z rousseau $
 */

/**
 * @file
 * @brief This keeps a list of Windows(R) types.
 */

#ifndef __wintypes_h__
#define __wintypes_h__

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef BYTE
	typedef unsigned char BYTE;
#endif
	typedef unsigned char UCHAR;
	typedef unsigned char *PUCHAR;
	typedef unsigned short USHORT;

#ifndef __COREFOUNDATION_CFPLUGINCOM__
	typedef unsigned long ULONG;
	typedef void *LPVOID;
#endif

	typedef const void *LPCVOID;
	typedef unsigned long DWORD;
	typedef unsigned long *PDWORD;
	typedef long LONG;
	typedef const char *LPCSTR;
	typedef const BYTE *LPCBYTE;
	typedef BYTE *LPBYTE;
	typedef DWORD *LPDWORD;
	typedef char *LPSTR;

	/* these types were deprecated but still used by old drivers and
	 * applications. So just declare and use them. */
	typedef LPSTR LPTSTR;
	typedef LPCSTR LPCTSTR;

	/* types unused by pcsc-lite */
	typedef short BOOL;
	typedef unsigned short WORD;
	typedef unsigned long *PULONG;

#ifdef __cplusplus
}
#endif

#endif
