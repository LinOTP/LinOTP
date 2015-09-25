#include <stdio.h>
#include <stdint.h>

#include "zeromem.h" // beinhaltet auch #include <errno.h> und <string.h>

#if !(defined(HAVE_MEMSET_S) && HAVE_MEMSET_S==1)
/* protect memset_s from compiler optimization */

// some compilers have support for: __attribute__((optimize("O0")))
int memset_s(void *s, size_t smax, int c, size_t n) {
    int err = 0;

    if (s == NULL) {
        return EINVAL;
    }
    if (smax > SIZE_MAX) {
        return E2BIG;
    }
    if (n > SIZE_MAX) {
        err = E2BIG;
        n = smax;
    }
    if (n > smax) {
        err = EOVERFLOW;
        n = smax;
    }

    volatile unsigned char *p = (unsigned char*)s;
    while (n-- > 0)
        *p++ = (unsigned char)c;

    return err;
}
#endif // HAVE_MEMSET_S


#if __SECURE_ZEROMEM==0
void secure_zeromem(void *b, size_t n) {
    volatile unsigned char *p = (unsigned char*)b;
    while (n-- > 0)
        *p++ = 0;
}
#endif