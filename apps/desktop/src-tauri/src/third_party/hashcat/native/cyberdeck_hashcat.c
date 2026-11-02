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

static void cd_setup_event (const u32 id, MAYBE_UNUSED hashcat_ctx_t *context,
                            MAYBE_UNUSED const void *buffer,
                            MAYBE_UNUSED const size_t length)
{
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
    default:
      break;
  }
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
  if (handle == NULL || handle->core == NULL || handle->session_attempted) return -1;
  if (!handle->options_initialized) return -1;
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
  ARG (temporary_outfile);
  ARG ("--limit");
  ARG (handle->candidate_limit);
  ARG ("--runtime");
  ARG (handle->runtime_limit);
  if (device_id != 0)
  {
    ARG ("--backend-devices");
    ARG (handle->device_selector);
  }
  ARG (hash_file);
  ARG (wordlist_file);
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
