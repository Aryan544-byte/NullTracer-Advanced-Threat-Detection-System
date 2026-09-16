/*
 * ioctl.h — NullTracer Kernel Driver
 * ===================================
 * Shared definitions between the kernel driver (NullTracerDrv.sys) and the
 * user-mode relay agent (nulltracer_agent.py / any C consumer).
 *
 * This header is intentionally kept free of kernel-only types so it can be
 * included in both kernel-mode and user-mode compilation units.
 *
 * IOCTL METHOD: METHOD_BUFFERED for all operations.  The kernel copies the
 * output buffer to user space automatically; no ProbeForWrite needed.
 */

#pragma once

#include <ntintsafe.h>

/* --------------------------------------------------------------------------
 * Device symbolic link — opened by user-mode callers via CreateFile
 * -------------------------------------------------------------------------- */
#define NULLTRACER_DEVICE_NAME      L"\\Device\\NullTracer"
#define NULLTRACER_SYMLINK_NAME     L"\\DosDevices\\NullTracer"
#define NULLTRACER_WIN32_NAME       L"\\\\.\\NullTracer"

/* --------------------------------------------------------------------------
 * Event type codes — mirrors engine/models.py EventType enum
 * -------------------------------------------------------------------------- */
#define NT_EVENT_PROCESS_CREATE     0x01
#define NT_EVENT_IMAGE_LOAD         0x02
#define NT_EVENT_REGISTRY_SET       0x03

/* --------------------------------------------------------------------------
 * NT_EVENT_RECORD — fixed-size event record written to the ring buffer.
 *
 * Fixed-size design rationale:
 *   - Ring buffer slots are uniform — no fragmentation, no heap pointers.
 *   - DeviceIoControl(METHOD_BUFFERED) copies the raw bytes; the agent just
 *     casts the buffer to an array of NT_EVENT_RECORD.
 *   - String fields are NUL-terminated UTF-16LE, truncated to field width.
 * -------------------------------------------------------------------------- */
#define NT_MAX_PATH_CCH     260     /* MAX_PATH in chars */
#define NT_MAX_CMDLINE_CCH  512     /* Command line in chars */
#define NT_MAX_REGKEY_CCH   256     /* Registry key path in chars */

#pragma pack(push, 1)
typedef struct _NT_EVENT_RECORD {
    ULONG64     Timestamp;          /* FILETIME (100-ns ticks since 1601) */
    ULONG       EventType;          /* NT_EVENT_PROCESS_CREATE etc. */
    ULONG       ProcessId;
    ULONG       ParentProcessId;
    ULONG       ThreadId;
    WCHAR       ImagePath[NT_MAX_PATH_CCH];
    WCHAR       CommandLine[NT_MAX_CMDLINE_CCH];
    WCHAR       RegistryKey[NT_MAX_REGKEY_CCH]; /* non-empty for REGISTRY_SET */
    WCHAR       RegistryValue[NT_MAX_PATH_CCH]; /* value name for REGISTRY_SET */
    ULONG       Reserved;           /* alignment pad */
} NT_EVENT_RECORD, *PNT_EVENT_RECORD;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * IOCTL codes
 *
 *   IOCTL_NULLTRACER_READ_EVENTS  — drain events from the ring buffer.
 *       Input:  ULONG max_records  (how many records the caller wants)
 *       Output: NT_EVENT_RECORD[]  (up to max_records records)
 *       Returns: bytes written = actual_count * sizeof(NT_EVENT_RECORD)
 *
 *   IOCTL_NULLTRACER_GET_STATS    — return ring buffer statistics.
 *       Input:  none
 *       Output: NT_STATS record
 * -------------------------------------------------------------------------- */
#define NULLTRACER_DEVICE_TYPE      FILE_DEVICE_UNKNOWN

#define IOCTL_NULLTRACER_READ_EVENTS \
    CTL_CODE(NULLTRACER_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_NULLTRACER_GET_STATS \
    CTL_CODE(NULLTRACER_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

#pragma pack(push, 1)
typedef struct _NT_STATS {
    ULONG64 TotalEventsProduced;    /* callbacks fired since driver load */
    ULONG64 TotalEventsConsumed;    /* IOCTL reads handed to user space */
    ULONG64 TotalEventsDropped;     /* ring full — event discarded */
    ULONG   RingCapacity;           /* max events in the ring buffer */
    ULONG   RingOccupancy;          /* events currently in the ring */
} NT_STATS, *PNT_STATS;
#pragma pack(pop)
