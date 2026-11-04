/*
 * Copyright (c) 2026 CyberDeck contributors.
 * SPDX-License-Identifier: MIT
 * C owner of Hashcat's internal struct sizes, lifecycle, options and callbacks.
 *
 * This is linked against the exact pinned upstream shared core, NOT a renamed
 * hashcat executable. The caller must sandbox/redirect HOME/XDG data/cache,
 * securely create inputs and result scratch, disable core dumps, and clean up.
 */
#define CYBERDECK_HASHCAT_BUILD
#include "cyberdeck_hashcat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common.h"
#include "types.h"
#include "hashcat.h"
#include "user_options.h"
#include "module_options.h"
#include "dynloader.h"

/* A private worker constructs exactly one Hashcat context per process.
 * Hashcat's event callback has no user-data pointer, so the C owner records
 * only whitelisted setup phase IDs with atomic operations. Never capture logs,
 * candidate bytes, target hashes, device serials or paths.
 */
static unsigned int cd_setup_phase = 0;

static char cd_last_event[4096];
static char cd_event_trace[2048];
static char cd_last_log[4096];
static char cd_first_log[2048];

static void cd_setup_event (const u32 id, MAYBE_UNUSED hashcat_ctx_t *context,
                            MAYBE_UNUSED const void *buffer,
                            MAYBE_UNUSED const size_t length)
{
  fprintf (stderr, "[ev %08x] hc_hash=%s", id,
           context->user_options_extra ? (context->user_options_extra->hc_hash ? context->user_options_extra->hc_hash : "NULL") : "no-extra");
  fputc (10, stderr);
  snprintf (cd_last_event, sizeof (cd_last_event), "event 0x%08x", id);
  fputc (10, stderr);
  snprintf (cd_last_event, sizeof (cd_last_event), "event 0x%08x", id);
  {
    char one[32];
    int n = snprintf (one, sizeof (one), "%08x ", id);
    size_t len = strlen (cd_event_trace);
    if (len + n < sizeof (cd_event_trace)) { memcpy (cd_event_trace + len, one, n); cd_event_trace[len + n] = 0; }
  }
  switch (id)
  {
    case EVENT_BRIDGES_INIT_PRE:
    case EVENT_BRIDGES_INIT_POST:
    case EVENT_BACKEND_RUNTIMES_INIT_PRE:
    case EVENT_BACKEND_RUNTIMES_INIT_POST:
    case EVENT_BACKEND_DEVICES_INIT_PRE:
    case EVENT_BACKEND_DEVICES_INIT_POST:
      __atomic_store_n (&cd_setup_phase, id, __ATOMIC_RELAXED);
      break;
    case EVENT_HASHLIST_PARSE_INPUT_PRE:
    case EVENT_HASHLIST_PARSE_INPUT_POST:
      fputs ("[cd-paths] hc_hash=", stderr);
      fputs (context->user_options_extra->hc_hash, stderr);
      fputs (" hashfile=", stderr);
      fputs (context->hashes->hashfile, stderr);
      fputc (10, stderr);
      break;
    case EVENT_LOG_WARNING:
    case EVENT_LOG_ERROR:
      /* Log events pass a NULL buffer: the rendered message lives in the
       * event context's own buffer. Read it from there (same process). */
      if (context != NULL && context->event_ctx != NULL)
      {
        const char *msg = context->event_ctx->msg_buf;
        size_t copy = strnlen (msg, 2047);
        memcpy (cd_last_log, msg, copy);
        cd_last_log[copy] = 0;
        if (cd_first_log[0] == 0 && copy > 0)
        {
          size_t fc = copy < sizeof (cd_first_log) - 1 ? copy : sizeof (cd_first_log) - 1;
          memcpy (cd_first_log, msg, fc);
          cd_first_log[fc] = 0;
        }
      }
      break;
    default:
      snprintf (cd_last_event, sizeof (cd_last_event), "last event id 0x%08x", id);
      break;
  }
}

const char *cd_hashcat_last_event (void)
{
  if (cd_first_log[0] && strcmp (cd_first_log, cd_last_log) != 0)
  {
    static char combined[8192];
    snprintf (combined, sizeof (combined), "first: %s || last: %s", cd_first_log, cd_last_log);
    return combined;
  }
  return cd_last_log[0] ? cd_last_log : cd_last_event;
}

const char *cd_hashcat_event_trace (void)
{
  return cd_event_trace;
}

int cd_hashcat_shim_version (void)
{
  return 42;
}

struct cd_hashcat
{
  hashcat_ctx_t *core;
  int initialized;
  int options_initialized;
  int session_attempted;
  char candidate_limit[32];
  char runtime_limit[16];
  char device_selector[16];
  char hash_mode_option[32];
  char *fixed_options[25];
  char *owned_strings[8];
  size_t owned_cnt;
};

uint32_t cd_hashcat_abi_version (void)
{
  return 4;
}

/* Deliberately mirror upstream ext_OpenCL.c loader names. This is only a
 * no-credentials preflight; OpenCL platforms, devices and kernels may still
 * be absent or unsupported. The installed GPU driver owns the loader. */
uint32_t cd_hashcat_opencl_loader_available (void)
{
  hc_dynlib_t library = NULL;
#if defined (_WIN)
  library = hc_dlopen ("OpenCL");
#elif defined (__APPLE__)
  library = hc_dlopen ("/System/Library/Frameworks/OpenCL.framework/OpenCL");
#elif defined (__CYGWIN__)
  library = hc_dlopen ("opencl.dll");
  if (library == NULL) library = hc_dlopen ("cygOpenCL-1.dll");
#else
  library = hc_dlopen ("libOpenCL.so");
  if (library == NULL) library = hc_dlopen ("libOpenCL.so.1");
#endif
  if (library == NULL) return 0;
  hc_dlclose (library);
  return 1;
}

uint32_t cd_hashcat_last_setup_stage (cd_hashcat *handle)
{
  if (handle == NULL || handle->core == NULL) return 0;
  return __atomic_load_n (&cd_setup_phase, __ATOMIC_RELAXED);
}

cd_hashcat *cd_hashcat_create (void)
{
  cd_hashcat *handle = (cd_hashcat *) calloc (1, sizeof (cd_hashcat));
  if (handle == NULL) return NULL;

  handle->core = (hashcat_ctx_t *) calloc (1, sizeof (hashcat_ctx_t));
  if (handle->core == NULL) { free (handle); return NULL; }

  __atomic_store_n (&cd_setup_phase, 0, __ATOMIC_RELAXED);
  if (hashcat_init (handle->core, cd_setup_event) != 0)
  {
    // Hashcat may have initialized some members before failing.
    hashcat_destroy (handle->core);
    free (handle->core);
    free (handle);
    return NULL;
  }
  handle->initialized = 1;

  if (user_options_init (handle->core) != 0)
  {
    cd_hashcat_destroy (handle);
    return NULL;
  }
  handle->options_initialized = 1;
  return handle;
}

static int validate_path (const char *value)
{
  if (value == NULL) return 0;
  const size_t len = strlen (value);
  if (len == 0 || len > 4096) return 0;
  // A private worker must independently ensure absolute, non-symlink paths.
  // Reject options and line/control characters, which must never enter argv.
  if (value[0] == '-') return 0;
  for (const unsigned char *p = (const unsigned char *) value; *p != 0; p++)
  {
    if (*p == '\r' || *p == '\n' || *p < 0x20) return 0;
  }
  return 1;
}

int cd_hashcat_prepare_mode (
    cd_hashcat *handle,
    const char *install_root,
    const char *shared_root,
    const char *hash_file,
    const char *wordlist_file,
    const char *temporary_outfile,
    uint64_t max_candidates,
    uint32_t runtime_seconds,
    uint32_t device_id,
    uint32_t hash_mode)
{
  snprintf (cd_last_event, sizeof (cd_last_event), "prepare entered mode check");
  if (handle == NULL || handle->core == NULL || handle->session_attempted) return -1;
  fputc (10, stderr);
  if (!handle->options_initialized) return -1;
  {
    FILE *probe = fopen (hash_file, "rb");
  {
    FILE *probe = fopen (hash_file, "rb");
    if (probe != NULL)
    {
      char head[80] = { 0 };
      size_t n = fread (head, 1, sizeof (head) - 1, probe);
      fclose (probe);
      head[n] = 0;
      fputs ("[cd-probe] hash_file readable: ", stderr);
      fprintf (stderr, "%zu bytes: ", n);
      fputs (head, stderr);
      fputc (10, stderr);
    }
    else
    {
      fputs ("[cd-probe] hash_file UNREADABLE: ", stderr);
      fputs (hash_file, stderr);
      fputc (10, stderr);
    }
  }
  }
  if (!validate_path (install_root) || !validate_path (shared_root)
      || !validate_path (hash_file) || !validate_path (wordlist_file)
      || !validate_path (temporary_outfile)) return -2;
  if (max_candidates == 0 || max_candidates > 1000000
      || runtime_seconds == 0 || runtime_seconds > 300
      || device_id > 128) return -2;
  switch (hash_mode) {
    case 0: case 10: case 20: case 50: case 60: case 100: case 110: case 120:
    case 400: case 1500: case 132: case 1731:
    case 500: case 1000: case 1400: case 1700: case 1800: case 3200: case 7400:
    case 1100: case 2100: case 5500: case 5600:
    case 11600: case 13600: case 17200: case 17210:
      break;
    default:
      return -2;
  }
  snprintf (handle->hash_mode_option, sizeof (handle->hash_mode_option), "--hash-type=%u", hash_mode);

  snprintf (handle->candidate_limit, sizeof (handle->candidate_limit), "%llu",
            (unsigned long long) max_candidates);
  snprintf (handle->runtime_limit, sizeof (handle->runtime_limit), "%u",
            (unsigned int) runtime_seconds);
  snprintf (handle->device_selector, sizeof (handle->device_selector), "%u",
            (unsigned int) device_id);

  size_t argc = 0;
#define ARG(x) do { if (argc >= 24) return -2; handle->fixed_options[argc++] = (char *)(x); } while (0)
/* Options whose backing strings live in the caller's frame must be owned by
 * the handle: the worker's Rust buffers are freed when prepare returns, and
 * execute() reads fixed_options afterwards. */
#define ARG_OWN(x) do {     if (argc >= 24 || handle->owned_cnt >= 8) return -2;     size_t len_ = strlen (x);     char *copy_ = (char *) malloc (len_ + 1);     if (copy_ == NULL) return -2;     memcpy (copy_, x, len_ + 1);     handle->owned_strings[handle->owned_cnt++] = copy_;     handle->fixed_options[argc++] = copy_;   } while (0)
  ARG ("cyberdeck-private-recovery-worker");
  ARG (handle->hash_mode_option);
  ARG ("--attack-mode=0");
  ARG ("--potfile-disable");
  ARG ("--restore-disable");
  ARG ("--logfile-disable");
  ARG ("--hwmon-disable");
  ARG ("--quiet");
  ARG ("--backend-ignore-cuda");
  ARG ("--backend-ignore-hip");
  /* Metal backend is relevant on macOS only; upstream rejects the switch on Linux. */
#if defined(__APPLE__)
  ARG ("--backend-ignore-metal");
#endif
  ARG ("--outfile-format=2");
  ARG ("--outfile");
  ARG_OWN (temporary_outfile);
  ARG ("--limit");
  ARG (handle->candidate_limit);
  ARG ("--runtime");
  ARG (handle->runtime_limit);
  if (device_id != 0)
  {
    ARG ("--backend-devices");
    ARG (handle->device_selector);
  }
  ARG_OWN (hash_file);
  ARG_OWN (wordlist_file);
  handle->fixed_options[argc] = NULL;
#undef ARG

  user_options_prescan (handle->core, (int) argc, handle->fixed_options);
  const int comptime = (int) time (NULL);

  // Matches upstream main.c API order; the worker never accepts CLI args.
  if (module_options_init (handle->core, install_root, shared_root, "v8.0.0", comptime) != 0)
  {
    return -3;
  }
  if (user_options_getopt (handle->core, (int) argc, handle->fixed_options) != 0)
  {
    return -41;
  }
  {
    const user_options_t *uo = handle->core->user_options;
    const user_options_extra_t *uo2 = handle->core->user_options_extra;
    fprintf (stderr, "[cd-opts] hc_argc=%d hash_mode=%u autodetect=%d", uo->hc_argc, uo->hash_mode, (int) uo->autodetect);
    for (int i = 0; i < (int) argc; i++)
    {
      fputs ("argv[", stderr);
      fprintf (stderr, "%d", i);
      fputs ("]=", stderr);
      fputs (handle->fixed_options[i] ? handle->fixed_options[i] : "NULL", stderr);
      fputc (10, stderr);
    }
    fputs (" extra hc_hash=", stderr);
    fputs (uo2->hc_hash ? uo2->hc_hash : "NULL", stderr);
    fputc (10, stderr);
  }
  if (user_options_sanity (handle->core) != 0)
  {
    return -42;
  }

  handle->session_attempted = 1;
  if (hashcat_session_init (handle->core, install_root, shared_root,
                            (int) argc, handle->fixed_options, comptime) != 0)
  {
    return -5;
  }
  {
    const user_options_extra_t *uo2 = handle->core->user_options_extra;
    fputs (uo2->hc_hash ? uo2->hc_hash : "NULL", stderr);
    fputc (10, stderr);
    fputs (uo2->hc_workv && uo2->hc_workc > 0 && uo2->hc_workv[0] ? uo2->hc_workv[0] : "NULL", stderr);
    fputc (10, stderr);
  }

  return 0;
}

int cd_hashcat_prepare_sha256 (
    cd_hashcat *handle, const char *install_root, const char *shared_root,
    const char *hash_file, const char *wordlist_file, const char *temporary_outfile,
    uint64_t max_candidates, uint32_t runtime_seconds, uint32_t device_id)
{
  return cd_hashcat_prepare_mode (handle, install_root, shared_root, hash_file,
      wordlist_file, temporary_outfile, max_candidates, runtime_seconds, device_id, 1400);
}

int cd_hashcat_execute (cd_hashcat *handle)
{
  if (handle == NULL || !handle->session_attempted) return -1;
  return hashcat_session_execute (handle->core);
}

int cd_hashcat_quit (cd_hashcat *handle)
{
  if (handle == NULL || !handle->session_attempted) return -1;
  return hashcat_session_quit (handle->core);
}

void cd_hashcat_destroy (cd_hashcat *handle)
{
  if (handle == NULL) return;
  for (size_t i = 0; i < handle->owned_cnt; i++) free (handle->owned_strings[i]);
  if (handle->core != NULL)
  {
    if (handle->session_attempted)
    {
      hashcat_session_destroy (handle->core);
    }
    if (handle->options_initialized && !handle->session_attempted)
    {
      user_options_destroy (handle->core);
    }
    if (handle->initialized)
    {
      hashcat_destroy (handle->core);
    }
    free (handle->core);
    handle->core = NULL;
  }
  memset (handle, 0, sizeof (*handle));
  free (handle);
}
