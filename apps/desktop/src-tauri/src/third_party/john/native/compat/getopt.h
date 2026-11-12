/* mingw compat: benign libc getopt interface. <unistd.h> does an angle
 * #include <getopt.h>; without this file the angle search hits -I. and
 * picks up john's src/getopt.h, whose #include "common.h" drags john's
 * memory.h into every TU before mem_map.h can #undef MEM_FREE (the
 * pre-set _JOHN_MEMORY_H guard then makes loader.c/wordlist.c's later
 * #include "memory.h" a no-op, so MEM_FREE becomes an implicit function
 * call). john's own quoted #include "getopt.h" still resolves to
 * src/getopt.h (directory-relative), so this file is only seen by
 * system headers that angle-include <getopt.h>. */
#ifndef JOHN_COMPAT_GETOPT_H
#define JOHN_COMPAT_GETOPT_H
extern char *optarg;
extern int optind, opterr, optopt;
int getopt(int argc, char *const argv[], const char *optstring);
#endif
