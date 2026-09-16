/*
 * callbacks.c — NullTracer Kernel Driver
 * ========================================
 * Registers and implements the three kernel notification callbacks:
 *
 *   1. PsSetCreateProcessNotifyRoutineEx  → NT_EVENT_PROCESS_CREATE
 *   2. PsSetLoadImageNotifyRoutineEx      → NT_EVENT_IMAGE_LOAD
 *   3. CmRegisterCallback                 → NT_EVENT_REGISTRY_SET
 *
 * Design rationale:
 *   Kernel callbacks give us synchronous, pre-execution visibility into every
 *   process creation and image load on the system.  Unlike ETW which requires
 *   a user-mode session and can drop events under load, these callbacks are
 *   in-process and loss-free up to the ring buffer capacity.
 *
 * IRQL notes:
 *   - PsSetCreateProcessNotifyRoutineEx fires at IRQL <= APC_LEVEL.
 *   - PsSetLoadImageNotifyRoutine fires at IRQL <= APC_LEVEL.
 *   - CmRegisterCallback fires at IRQL <= APC_LEVEL.
 *   All three can call RingBufWrite which acquires a KSPIN_LOCK (safe up to
 *   DISPATCH_LEVEL).
 *
 * Command-line capture:
 *   PEB.ProcessParameters is user-mode memory.  We use
 *   ZwQueryInformationProcess to get the PROCESS_BASIC_INFORMATION, then
 *   attach to the target process with KeStackAttachProcess and safely read
 *   the RTL_USER_PROCESS_PARAMETERS struct.  All reads are wrapped in
 *   __try/__except to handle bad pointers gracefully.
 */

#include <ntddk.h>
#include <wdm.h>
#include <aux_klib.h>

#include "ioctl.h"
#include "ringbuf.h"
#include "callbacks.h"

/* --------------------------------------------------------------------------
 * Externals — ring buffer lives in NullTracerDrv.c
 * -------------------------------------------------------------------------- */
extern NT_RING_BUFFER g_Ring;

/* --------------------------------------------------------------------------
 * Registry callback cookie (opaque LARGE_INTEGER)
 * -------------------------------------------------------------------------- */
static LARGE_INTEGER g_RegCookie;

/* --------------------------------------------------------------------------
 * Helper: get current FILETIME as ULONG64
 * -------------------------------------------------------------------------- */
static ULONG64 _GetTimestamp(VOID)
{
    LARGE_INTEGER SystemTime;
    KeQuerySystemTime(&SystemTime);
    return (ULONG64)SystemTime.QuadPart;
}

/* --------------------------------------------------------------------------
 * Helper: safely copy a UNICODE_STRING into a fixed-width WCHAR buffer.
 * Truncates to (BufCch - 1) characters and always NUL-terminates.
 * -------------------------------------------------------------------------- */
static VOID _CopyUnicodeStringSafe(
    _Out_writes_(BufCch) WCHAR *Buf,
    _In_  ULONG          BufCch,
    _In_  PUNICODE_STRING Src)
{
    ULONG CopyCch;

    if (!Src || !Src->Buffer || Src->Length == 0) {
        Buf[0] = L'\0';
        return;
    }

    CopyCch = Src->Length / sizeof(WCHAR);
    if (CopyCch >= BufCch) {
        CopyCch = BufCch - 1;
    }

    RtlCopyMemory(Buf, Src->Buffer, CopyCch * sizeof(WCHAR));
    Buf[CopyCch] = L'\0';
}

/* --------------------------------------------------------------------------
 * Helper: read CommandLine from a target process's PEB.
 *
 * Steps:
 *   1. Open the process by PID.
 *   2. Query PROCESS_BASIC_INFORMATION to get PebBaseAddress.
 *   3. KeStackAttachProcess to map the user-mode PEB.
 *   4. Read PEB->ProcessParameters->CommandLine under __try.
 *   5. Detach.
 * -------------------------------------------------------------------------- */
static VOID _ReadCommandLine(
    _In_  HANDLE ProcessId,
    _Out_writes_(BufCch) WCHAR *Buf,
    _In_  ULONG  BufCch)
{
    NTSTATUS                    Status;
    HANDLE                      hProcess    = NULL;
    PEPROCESS                   Process     = NULL;
    PROCESS_BASIC_INFORMATION   Pbi         = {0};
    ULONG                       ReturnLen   = 0;
    KAPC_STATE                  ApcState;
    PPEB                        Peb         = NULL;
    PRTL_USER_PROCESS_PARAMETERS Params     = NULL;
    OBJECT_ATTRIBUTES           ObjAttr;
    CLIENT_ID                   ClientId;

    Buf[0] = L'\0';

    /* Lookup PEPROCESS by PID */
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return;
    }

    /* Attach to the target process address space to read user-mode memory */
    KeStackAttachProcess(Process, &ApcState);

    __try {
        Peb = PsGetProcessPeb(Process);
        if (!Peb) {
            __leave;
        }

        Params = Peb->ProcessParameters;
        if (!Params) {
            __leave;
        }

        _CopyUnicodeStringSafe(Buf, BufCch, &Params->CommandLine);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Buf[0] = L'\0';
    }

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);
}

/* --------------------------------------------------------------------------
 * 1. Process-create callback
 *    Registered via PsSetCreateProcessNotifyRoutineEx
 * -------------------------------------------------------------------------- */
VOID NullTracerCreateProcessCallback(
    _Inout_ PEPROCESS Process,
    _In_    HANDLE    ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    NT_EVENT_RECORD Ev = {0};

    /* CreateInfo == NULL  → process termination; we only care about creation */
    if (!CreateInfo) {
        return;
    }

    Ev.Timestamp        = _GetTimestamp();
    Ev.EventType        = NT_EVENT_PROCESS_CREATE;
    Ev.ProcessId        = HandleToUlong(ProcessId);
    Ev.ParentProcessId  = HandleToUlong(CreateInfo->ParentProcessId);
    Ev.ThreadId         = HandleToUlong(PsGetCurrentThreadId());

    /* Image path comes directly from CreateInfo — no attach needed */
    if (CreateInfo->ImageFileName) {
        _CopyUnicodeStringSafe(
            Ev.ImagePath, ARRAYSIZE(Ev.ImagePath),
            CreateInfo->ImageFileName);
    }

    /* CommandLine requires PEB read */
    _ReadCommandLine(ProcessId, Ev.CommandLine, ARRAYSIZE(Ev.CommandLine));

    RingBufWrite(&g_Ring, &Ev);

    UNREFERENCED_PARAMETER(Process);
}

/* --------------------------------------------------------------------------
 * 2. Image-load callback
 *    Registered via PsSetLoadImageNotifyRoutineEx
 * -------------------------------------------------------------------------- */
VOID NullTracerLoadImageCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo)
{
    NT_EVENT_RECORD Ev = {0};

    Ev.Timestamp       = _GetTimestamp();
    Ev.EventType       = NT_EVENT_IMAGE_LOAD;
    Ev.ProcessId       = HandleToUlong(ProcessId);
    Ev.ParentProcessId = 0;
    Ev.ThreadId        = HandleToUlong(PsGetCurrentThreadId());

    if (FullImageName) {
        _CopyUnicodeStringSafe(
            Ev.ImagePath, ARRAYSIZE(Ev.ImagePath),
            FullImageName);
    }

    RingBufWrite(&g_Ring, &Ev);

    UNREFERENCED_PARAMETER(ImageInfo);
}

/* --------------------------------------------------------------------------
 * 3. Registry callback
 *    Registered via CmRegisterCallback — fires for every registry operation.
 *    We filter for RegNtSetValueKey only (RegistrySet equivalent).
 * -------------------------------------------------------------------------- */
NTSTATUS NullTracerRegistryCallback(
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    REG_NOTIFY_CLASS    NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    NT_EVENT_RECORD     Ev          = {0};

    /* We only care about pre-set-value notifications */
    if (NotifyClass != RegNtPreSetValueKey) {
        return STATUS_SUCCESS;
    }

    PREG_SET_VALUE_KEY_INFORMATION Info =
        (PREG_SET_VALUE_KEY_INFORMATION)Argument2;

    if (!Info) {
        return STATUS_SUCCESS;
    }

    Ev.Timestamp        = _GetTimestamp();
    Ev.EventType        = NT_EVENT_REGISTRY_SET;
    Ev.ProcessId        = HandleToUlong(PsGetCurrentProcessId());
    Ev.ParentProcessId  = 0;
    Ev.ThreadId         = HandleToUlong(PsGetCurrentThreadId());

    /* Resolve the registry key path from the object */
    UNICODE_STRING  KeyPath = {0};
    PCUNICODE_STRING pKeyPath = NULL;
    NTSTATUS        RegStatus;

    RegStatus = CmCallbackGetKeyObjectIDEx(
        &g_RegCookie,
        Info->Object,
        NULL,
        &pKeyPath,
        0);

    if (NT_SUCCESS(RegStatus) && pKeyPath) {
        _CopyUnicodeStringSafe(
            Ev.RegistryKey, ARRAYSIZE(Ev.RegistryKey),
            (PUNICODE_STRING)pKeyPath);
        CmCallbackReleaseKeyObjectIDEx(pKeyPath);
    }

    if (Info->ValueName) {
        _CopyUnicodeStringSafe(
            Ev.RegistryValue, ARRAYSIZE(Ev.RegistryValue),
            Info->ValueName);
    }

    RingBufWrite(&g_Ring, &Ev);

    UNREFERENCED_PARAMETER(CallbackContext);
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * CallbacksRegister — called from DriverEntry
 * -------------------------------------------------------------------------- */
NTSTATUS CallbacksRegister(VOID)
{
    NTSTATUS Status;
    UNICODE_STRING Altitude;

    /* Process-create notifications */
    Status = PsSetCreateProcessNotifyRoutineEx(
        NullTracerCreateProcessCallback,
        FALSE);     /* FALSE = register, TRUE = deregister */

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[NullTracer] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", Status));
        return Status;
    }

    /* Image-load notifications */
    Status = PsSetLoadImageNotifyRoutineEx(
        NullTracerLoadImageCallback,
        PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE);  /* all image loads */

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[NullTracer] PsSetLoadImageNotifyRoutineEx failed: 0x%08X\n", Status));
        /* Roll back process callback */
        PsSetCreateProcessNotifyRoutineEx(
            NullTracerCreateProcessCallback, TRUE);
        return Status;
    }

    /* Registry callback — use a unique altitude string */
    RtlInitUnicodeString(&Altitude, L"385200");
    Status = CmRegisterCallbackEx(
        NullTracerRegistryCallback,
        &Altitude,
        NULL,
        NULL,
        &g_RegCookie,
        NULL);

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[NullTracer] CmRegisterCallbackEx failed: 0x%08X\n", Status));
        PsSetCreateProcessNotifyRoutineEx(
            NullTracerCreateProcessCallback, TRUE);
        PsRemoveLoadImageNotifyRoutine(
            NullTracerLoadImageCallback);
        return Status;
    }

    KdPrint(("[NullTracer] All callbacks registered successfully.\n"));
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * CallbacksUnregister — called from DriverUnload
 * -------------------------------------------------------------------------- */
VOID CallbacksUnregister(VOID)
{
    CmUnRegisterCallback(g_RegCookie);

    PsRemoveLoadImageNotifyRoutine(
        NullTracerLoadImageCallback);

    PsSetCreateProcessNotifyRoutineEx(
        NullTracerCreateProcessCallback, TRUE);

    KdPrint(("[NullTracer] All callbacks unregistered.\n"));
}
