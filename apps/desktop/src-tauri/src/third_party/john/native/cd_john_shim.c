/* CyberDeck's john DLL shim: exports the entry the worker calls. john's
 * full CLI flow runs with a worker-constructed argv; its exit() maps to the
 * worker's exit-status protocol (same contract as the hashcat session). */
#include "params.h"	/* JOHN_VERSION / JUMBO_POSTFIX / JUMBO_VERSION */
#include "version.h"	/* JTR_GIT_VERSION = JUMBO_VERSION "-$" (the exact
			 * string "john --list=build-info" prints on its
			 * "Version:" line, listconf.c:156) */

__declspec(dllexport) int cd_john_main(int argc, char **argv) {
    extern int main(int argc, char **argv);
    return main(argc, argv);
}

__declspec(dllexport) const char *cd_john_version(void) {
    return JTR_GIT_VERSION;
}
