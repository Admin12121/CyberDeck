/* mingw compat: POSIX stpcpy(3). UCRT and mingw-w64 runtime export no
 * stpcpy symbol, but gcc -O2's loop idiom recognition rewrites
 * strcpy+scan patterns (e.g. jumbo.c jtr_basename_r) into stpcpy() calls,
 * so the linker needs a real definition. Built with
 * -fno-tree-loop-distribute-patterns so this implementation's own copy
 * loop is not rewritten back into a stpcpy call. */
#include <stddef.h>
char *stpcpy(char *dst, const char *src)
{
	while ((*dst++ = *src++))
		;
	return dst - 1;
}
