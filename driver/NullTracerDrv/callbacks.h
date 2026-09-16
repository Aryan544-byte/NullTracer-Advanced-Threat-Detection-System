/*
 * callbacks.h — NullTracer Kernel Driver
 * ========================================
 * Forward declarations for functions defined in callbacks.c.
 */

#pragma once

#include <ntddk.h>

/* --------------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------------- */

/*
 * CallbacksRegister — register all three kernel callbacks.
 * Call from DriverEntry at IRQL == PASSIVE_LEVEL.
 * Rolls back already-registered callbacks on partial failure.
 */
NTSTATUS CallbacksRegister(VOID);

/*
 * CallbacksUnregister — deregister all three callbacks in reverse order.
 * Call from DriverUnload at IRQL == PASSIVE_LEVEL.
 */
VOID CallbacksUnregister(VOID);

/* --------------------------------------------------------------------------
 * Callback prototypes (defined in callbacks.c)
 * -------------------------------------------------------------------------- */

VOID NullTracerCreateProcessCallback(
    _Inout_     PEPROCESS           Process,
    _In_        HANDLE              ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

VOID NullTracerLoadImageCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo);

NTSTATUS NullTracerRegistryCallback(
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2);
