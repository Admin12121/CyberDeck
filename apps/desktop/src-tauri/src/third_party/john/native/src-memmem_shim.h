/* MSYS header visibility shim for the vendored john build: msys headers omit
 * the POSIX getopt interface for user compiles, while the msys-2.0 runtime
 * still exports those symbols. Force-including this header restores the
 * declarations on every translation unit.
 *
 * memmem/strcasestr deliberately have NO shims here: ucrt64 exports neither,
 * so the UCRT64 configure leaves HAVE_MEMMEM/HAVE_STRCASESTR undefined and
 * john's own jumbo.h/jumbo.c pair provides both (jumbo.h renames memmem to
 * jtr_memmem and declares strcasestr; jumbo.c defines them). Shadowing them
 * with macros would collide with those definitions — that shadowing was only
 * ever needed by the sandbox hybrid, whose configure ran under the msys
 * cygwin gcc (cygwin libc exports both, so john's definitions were compiled
 * out while the mingw build still needed call-site shims). */
#include <string.h>
#include <unistd.h>
#include <ctype.h>
extern char *optarg;
extern int optind, opterr, optopt;
int getopt(int argc, char *const argv[], const char *optstring);
