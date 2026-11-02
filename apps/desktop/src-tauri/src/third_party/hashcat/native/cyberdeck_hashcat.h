/*
 * Copyright (c) 2026 CyberDeck contributors.
 * SPDX-License-Identifier: MIT
 *
 * Narrow, versioned ABI over the pinned Hashcat native core. No upstream
 * structs or general-purpose CLI strings cross this boundary.
 */
#ifndef CYBERDECK_HASHCAT_ABI_H
#define CYBERDECK_HASHCAT_ABI_H

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
# if defined(CYBERDECK_HASHCAT_BUILD)
#  define CD_HC_API __declspec(dllexport)
# else
#  define CD_HC_API __declspec(dllimport)
# endif
#else
# define CD_HC_API __attribute__((visibility("default")))
#endif

typedef struct cd_hashcat cd_hashcat;

/* Fixed ABI version. Caller must reject any unexpected value. */
CD_HC_API uint32_t cd_hashcat_abi_version(void);
CD_HC_API uint32_t cd_hashcat_opencl_loader_available(void);

/* Returns the last recognized setup phase event, never raw event log text.
 * Designed for one-session-per-private-worker diagnostics only. */
CD_HC_API uint32_t cd_hashcat_last_setup_stage(cd_hashcat *context);

/* Allocates an upstream context. No device or hash is loaded yet. */
CD_HC_API cd_hashcat *cd_hashcat_create(void);

/*
 * Selected raw digest modes MD5(0), SHA-1(100), SHA-256(1400), SHA-512(1700)
 * with straight wordlist attack 0 are permitted. No arbitrary mode/flags.
 * All paths must be trusted absolute paths within a worker-owned scope.
 * max_candidates in [1,1000000], runtime_seconds in [1,300].
 * device_id=0 selects the backend default, otherwise 1..128.
 *
 * Returns 0 for initialized; a negative error otherwise.
 * A failed attempt must be followed by cd_hashcat_destroy(), not reused.
 */
CD_HC_API int cd_hashcat_prepare_mode(
    cd_hashcat *context,
    const char *install_root,
    const char *shared_root,
    const char *hash_file,
    const char *wordlist_file,
    const char *temporary_outfile,
    uint64_t max_candidates,
    uint32_t runtime_seconds,
    uint32_t device_id,
    uint32_t hash_mode);

/* Backward-compatible SHA-256 adapter (mode 1400). */
CD_HC_API int cd_hashcat_prepare_sha256(
    cd_hashcat *context,
    const char *install_root,
    const char *shared_root,
    const char *hash_file,
    const char *wordlist_file,
    const char *temporary_outfile,
    uint64_t max_candidates,
    uint32_t runtime_seconds,
    uint32_t device_id);

/* Execute synchronously. This call must run in a dedicated isolated worker. */
CD_HC_API int cd_hashcat_execute(cd_hashcat *context);

/* Cooperative cancellation; the supervising worker may be killed on hang. */
CD_HC_API int cd_hashcat_quit(cd_hashcat *context);

/* Idempotent cleanup of session and core. Not valid concurrently with execute. */
CD_HC_API void cd_hashcat_destroy(cd_hashcat *context);

#ifdef __cplusplus
}
#endif
#endif
