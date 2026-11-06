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
 * Selected raw digest modes MD5(0), SHA-1(100), NTLM(1000), SHA-256(1400), SHA-512(1700)
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

/*
 * Asynchronous alternative to cd_hashcat_execute(). Starts the same session
 * path on a shim-owned thread and returns 0 once it is running, -1 when the
 * context is invalid or an execute (either form) already ran: exactly one
 * execute per context, and cd_hashcat_destroy() still requires that no
 * session is in flight (join with cd_hashcat_execute_finish() first).
 *
 * While the session runs, the execute thread self-reports aggregate progress
 * counters into pinned snapshot fields every 200 ms; it is the only caller of
 * upstream status on the shared context, so cd_hashcat_poll_status() never
 * touches the live run itself. Counters are aggregate numbers only — word
 * counts and cracked-digest counts, never candidate bytes, hashes or names.
 */
CD_HC_API int cd_hashcat_execute_async(cd_hashcat *context);

/*
 * Snapshot reader for the asynchronous form. Returns 1 and fills the out
 * parameters (NULL tolerated) from the latest self-reported snapshot while
 * the session is running and has reported at least once: tried is upstream's
 * words-done total summed over salts, budget is the prepare-time candidate
 * limit (the operator bound, not a hashcat-derived total — a multi-hash
 * target can legitimately let tried exceed it), cracked is the number of
 * target digests cracked so far. Returns 0 when there is nothing to report
 * yet (session starting up) or the session has finished; -1 on invalid use
 * (no context, no prepared session).
 */
CD_HC_API int cd_hashcat_poll_status(cd_hashcat *context, uint64_t *tried, uint64_t *budget, uint32_t *cracked);

/*
 * Waits for the asynchronous session thread and returns the same status code
 * the synchronous cd_hashcat_execute() would have. timeout_ms bounds the
 * wait (0 waits without bound); -2 means the timeout expired with the session
 * still running, and the call may be repeated. Joins the thread exactly once.
 */
CD_HC_API int cd_hashcat_execute_finish(cd_hashcat *context, uint32_t timeout_ms);

/* Cooperative cancellation; the supervising worker may be killed on hang. */
CD_HC_API int cd_hashcat_quit(cd_hashcat *context);

/* Diagnostics: last captured event-log line and a shim build probe. */
CD_HC_API const char *cd_hashcat_last_event(void);
CD_HC_API int cd_hashcat_shim_version(void);
CD_HC_API const char *cd_hashcat_event_trace(void);

/* Idempotent cleanup of session and core. Not valid concurrently with execute. */
CD_HC_API void cd_hashcat_destroy(cd_hashcat *context);

#ifdef __cplusplus
}
#endif
#endif
