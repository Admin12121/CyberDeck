/* MSYS header visibility shim for the vendored john build: the msys header
 * set hides GNU extensions (memmem/strcasestr) behind visibility macros the
 * john build flags do not enable. Provide byte-equivalent static shims. */
#include <string.h>
#include <unistd.h>
#include <ctype.h>
/* msys headers omit the POSIX getopt interface for user compiles; the
 * msys-2.0 runtime still exports these symbols. */
extern char *optarg;
extern int optind, opterr, optopt;
int getopt(int argc, char *const argv[], const char *optstring);
#ifndef JOHN_MEMMEM_SHIM_H
#define JOHN_MEMMEM_SHIM_H
static void *john_memmem_shim(const void *h, unsigned long hl, const void *n, unsigned long nl) {
    if (!n || !nl || hl < nl) return (void *)0;
    const char *hay = (const char *)h;
    const char *nee = (const char *)n;
    for (unsigned long i = 0; i <= hl - nl; i++) {
        unsigned long j = 0;
        while (j < nl && hay[i + j] == nee[j]) j++;
        if (j == nl) return (void *)(hay + i);
    }
    return (void *)0;
}
static char *john_strcasestr_shim(const char *hay, const char *nee) {
    for (; *hay; hay++) {
        const char *a = hay;
        const char *b = nee;
        while (*a && *b && tolower((unsigned char)*a) == tolower((unsigned char)*b)) { a++; b++; }
        if (!*b) return (char *)hay;
    }
    return (char *)0;
}
#define memmem(h, hl, n, nl) john_memmem_shim(h, hl, n, nl)
#define strcasestr(h, n) john_strcasestr_shim(h, n)
#endif
