/*
 * NullTracerDrv.c — NullTracer Kernel Driver
 * ============================================
 * Entry point and IRP dispatch for the NullTracer kernel-mode driver.
 *
 * This driver:
 *   1. Creates a WDM device object at \Device\NullTracer and exposes it via
 *      the Win32 symlink \DosDevices\NullTracer (\\.\ NullTracer).
 *   2. Initialises the ring buffer (NonPagedPool).
 *   3. Registers the three kernel notification callbacks (callbacks.c).
 *   4. Handles IRP_MJ_DEVICE_CONTROL for the two IOCTLs:
 *        IOCTL_NULLTRACER_READ_EVENTS — drain events to user space.
 *        IOCTL_NULLTRACER_GET_STATS   — return ring buffer statistics.
 *   5. Handles IRP_MJ_CREATE / IRP_MJ_CLOSE (trivial success).
 *   6. On DriverUnload: deregisters callbacks, destroys ring buffer,
 *      deletes symlink and device.
 *
 * Build environment: Windows Driver Kit (WDK) 10 + MSVC (x64 Release).
 * Minimum OS: Windows 10 1903 (for PsSetLoadImageNotifyRoutineEx).
 *
 * Test-signing: compile with /INTEGRITYCHECK linker flag and sign with
 * setup_testsign.ps1 before loading on a test VM with test-signing enabled.
 */

#include <ntddk.h>
#include <wdm.h>

#include "ioctl.h"
#include "ringbuf.h"
#include "callbacks.h"

/* --------------------------------------------------------------------------
 * Global ring buffer — shared between this file and callbacks.c
 * -------------------------------------------------------------------------- */
NT_RING_BUFFER g_Ring;

/* --------------------------------------------------------------------------
 * Forward declarations
 * -------------------------------------------------------------------------- */
DRIVER_UNLOAD           NullTracerUnload;
DRIVER_DISPATCH         NullTracerDispatchCreateClose;
DRIVER_DISPATCH         NullTracerDispatchDeviceControl;

/* --------------------------------------------------------------------------
 * IRP_MJ_CREATE / IRP_MJ_CLOSE — trivial success
 * -------------------------------------------------------------------------- */
NTSTATUS NullTracerDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * IRP_MJ_DEVICE_CONTROL
 * -------------------------------------------------------------------------- */
NTSTATUS NullTracerDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION  Stack       = IoGetCurrentIrpStackLocation(Irp);
    ULONG               IoCtlCode   = Stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID               SysBuf      = Irp->AssociatedIrp.SystemBuffer;
    ULONG               InLen       = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG               OutLen      = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS            Status      = STATUS_SUCCESS;
    ULONG_PTR           Information = 0;

    switch (IoCtlCode) {

    /* ---------------------------------------------------------------------- */
    case IOCTL_NULLTRACER_READ_EVENTS:
    {
        /*
         * Input:  ULONG max_records  (how many records the caller can accept).
         * Output: NT_EVENT_RECORD[]
         *
         * We read up to min(max_records, OutLen / sizeof(NT_EVENT_RECORD)) events.
         */
        ULONG MaxFromCaller = 0;
        ULONG MaxFromBuf    = OutLen / (ULONG)sizeof(NT_EVENT_RECORD);
        ULONG MaxRecords;
        ULONG Copied;

        if (InLen >= sizeof(ULONG)) {
            RtlCopyMemory(&MaxFromCaller, SysBuf, sizeof(ULONG));
        }

        MaxRecords = (MaxFromCaller == 0 || MaxFromCaller > MaxFromBuf)
                     ? MaxFromBuf
                     : MaxFromCaller;

        if (MaxRecords == 0) {
            Status      = STATUS_BUFFER_TOO_SMALL;
            Information = 0;
            break;
        }

        Copied = RingBufReadBatch(&g_Ring, (PNT_EVENT_RECORD)SysBuf, MaxRecords);
        Information = (ULONG_PTR)(Copied * sizeof(NT_EVENT_RECORD));
        break;
    }

    /* ---------------------------------------------------------------------- */
    case IOCTL_NULLTRACER_GET_STATS:
    {
        if (OutLen < sizeof(NT_STATS)) {
            Status      = STATUS_BUFFER_TOO_SMALL;
            Information = 0;
            break;
        }

        RingBufGetStats(&g_Ring, (PNT_STATS)SysBuf);
        Information = sizeof(NT_STATS);
        break;
    }

    /* ---------------------------------------------------------------------- */
    default:
        Status      = STATUS_INVALID_DEVICE_REQUEST;
        Information = 0;
        break;
    }

    Irp->IoStatus.Status      = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

/* --------------------------------------------------------------------------
 * DriverUnload — clean shutdown in reverse-init order
 * -------------------------------------------------------------------------- */
VOID NullTracerUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING SymLink;

    KdPrint(("[NullTracer] Unloading...\n"));

    /* 1. Deregister callbacks first — ensures no new events arrive */
    CallbacksUnregister();

    /* 2. Destroy the ring buffer */
    RingBufDestroy(&g_Ring);

    /* 3. Delete the Win32 symbolic link */
    RtlInitUnicodeString(&SymLink, NULLTRACER_SYMLINK_NAME);
    IoDeleteSymbolicLink(&SymLink);

    /* 4. Delete the device object */
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    KdPrint(("[NullTracer] Unloaded cleanly.\n"));
}

/* --------------------------------------------------------------------------
 * DriverEntry — initialise everything
 * -------------------------------------------------------------------------- */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS        Status;
    UNICODE_STRING  DeviceName;
    UNICODE_STRING  SymLinkName;
    PDEVICE_OBJECT  DeviceObject = NULL;

    KdPrint(("[NullTracer] DriverEntry — NullTracer v1.0.0 loading...\n"));

    /* ------------------------------------------------------------------ */
    /* Step 1: Create the device object                                    */
    /* ------------------------------------------------------------------ */
    RtlInitUnicodeString(&DeviceName, NULLTRACER_DEVICE_NAME);

    Status = IoCreateDevice(
        DriverObject,
        0,                      /* no per-device extension needed */
        &DeviceName,
        NULLTRACER_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                  /* not exclusive */
        &DeviceObject);

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[NullTracer] IoCreateDevice failed: 0x%08X\n", Status));
        return Status;
    }

    /* Use buffered I/O — kernel copies between system buffer and user buffer */
    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    /* ------------------------------------------------------------------ */
    /* Step 2: Create the Win32 symbolic link                             */
    /* ------------------------------------------------------------------ */
    RtlInitUnicodeString(&SymLinkName, NULLTRACER_SYMLINK_NAME);

    Status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("[NullTracer] IoCreateSymbolicLink failed: 0x%08X\n", Status));
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    /* ------------------------------------------------------------------ */
    /* Step 3: Initialise the ring buffer                                 */
    /* ------------------------------------------------------------------ */
    Status = RingBufInit(&g_Ring, NULLTRACER_RING_CAPACITY);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("[NullTracer] RingBufInit failed: 0x%08X\n", Status));
        IoDeleteSymbolicLink(&SymLinkName);
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    /* ------------------------------------------------------------------ */
    /* Step 4: Register kernel notification callbacks                     */
    /* ------------------------------------------------------------------ */
    Status = CallbacksRegister();
    if (!NT_SUCCESS(Status)) {
        KdPrint(("[NullTracer] CallbacksRegister failed: 0x%08X\n", Status));
        RingBufDestroy(&g_Ring);
        IoDeleteSymbolicLink(&SymLinkName);
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    /* ------------------------------------------------------------------ */
    /* Step 5: Wire up the IRP dispatch table                             */
    /* ------------------------------------------------------------------ */
    DriverObject->DriverUnload                              = NullTracerUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]             = NullTracerDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]              = NullTracerDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]     = NullTracerDispatchDeviceControl;

    KdPrint(("[NullTracer] Loaded successfully. Device: %wZ\n", &DeviceName));
    return STATUS_SUCCESS;
}
