/** #pragma once **/
#ifndef __zeromem__h
#define __zeromem__h

#include <errno.h>  // include memset_s errors
#include <string.h> // include original definition of memset_s or explicit_bzero
#include <stddef.h> // include declaration of size_t

// By default, we do not have a better replacement for function "secure_zeromem"...
#define __SECURE_ZEROMEM 0

// Define function attribute which will disable call optimizations...
#if defined(HAVE_FUNC_ATTRIBUTE_OPTIMIZE) && HAVE_FUNC_ATTRIBUTE_OPTIMIZE==1
#define __GCC_NO_OPTIMIZE __attribute__((optimize("O0")))
#else
#define __GCC_NO_OPTIMIZE
#endif


/*
 * The function "explicit_bzero(void *s, rsize_t)" exists on Free BSD
 * based operating systems
 */
#if defined(HAVE_EXPLICIT_BZERO) && HAVE_EXPLICIT_BZERO==1 // "explicit_bzero" defined...
#if __SECURE_ZEROMEM==0

// instead of "secure_zeromem", we should use "explicit_bzero"...
inline void secure_zeromem(void *buffer, size_t size) {
	explicit_bzero(buffer, size);
}
#undef  __SECURE_ZEROMEM
#define __SECURE_ZEROMEM 1

#endif // __SECURE_ZEROMEM
#endif // HAVE_EXPLICIT_BZERO


/*
 * The function "memset_s(void *s, rsize_t, int, rsize_t)" exists on Mac OS X
 * based operating systems, or in C11
 */
#if defined(HAVE_MEMSET_S) && HAVE_MEMSET_S==1 // "memset_s" defined...
#if __SECURE_ZEROMEM==0

// instead of "secure_zeromem", we should use "memset_s"...
inline void secure_zeromem(void *buffer, size_t size) {
	memset_s(buffer, size, 0, size);
}
#undef  __SECURE_ZEROMEM
#define __SECURE_ZEROMEM 1

#endif // __SECURE_ZEROMEM
#else  // memset_s

// When "memset_s" is not available, then define our own version...
int __GCC_NO_OPTIMIZE memset_s(void *s, size_t smax, int c, size_t n);

#endif // memset_s


#if __SECURE_ZEROMEM==0
// there is not better replacement for function "secure_zeromem", declare new...
void __GCC_NO_OPTIMIZE secure_zeromem(void *b, size_t n);
#endif

#define blow(buffer, size) secure_zeromem(buffer, size)

#endif // __zeromem__h
