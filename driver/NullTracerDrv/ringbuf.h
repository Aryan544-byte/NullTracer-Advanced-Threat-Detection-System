/*
 * ringbuf.h — NullTracer Kernel Driver
 * ======================================
 * Single-producer / single-consumer lock-protected ring buffer for
 * NT_EVENT_RECORD objects, allocated from NonPagedPool.
 *
 * WHY NonPagedPool:
 *   Kernel callbacks (PsSetCreateProcessNotifyRoutineEx etc.) can fire at
 *   IRQL <= APC_LEVEL, but we protect writes with a KSPIN_LOCK which raises
 *   IRQL to DISPATCH_LEVEL. At DISPATCH_LEVEL only NonPagedPool memory may
 *   be touched — paged memory would cause a BSOD (IRQL_NOT_LESS_OR_EQUAL).
 *
 * WHY fixed-capacity:
 *   Dynamic resizing at high IRQL is unsafe. A pre-allocated, fixed-size
 *   power-of-two ring allows lock-free index arithmetic without division.
 */

#pragma once

#include <wdm.h>
#include "ioctl.h"

#define NULLTRACER_RING_CAPACITY    4096    /* must be power-of-two */

typedef struct _NT_RING_BUFFER {
    NT_EVENT_RECORD *Slots;         /* NonPagedPool array of RING_CAPACITY */
    ULONG           Capacity;       /* == NULLTRACER_RING_CAPACITY */
    ULONG           Mask;           /* == Capacity - 1 */
    ULONG           Head;           /* producer write index */
    ULONG           Tail;           /* consumer read index */
    KSPIN_LOCK      Lock;           /* protects Head; Tail is consumer-only */

    /* Diagnostics */
    ULONG64         TotalProduced;
    ULONG64         TotalConsumed;
    ULONG64         TotalDropped;
} NT_RING_BUFFER, *PNT_RING_BUFFER;


/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

/*
 * RingBufInit — allocate and initialise the ring buffer.
 * Call once from DriverEntry (IRQL == PASSIVE_LEVEL).
 * Returns STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES.
 */
NTSTATUS RingBufInit(_Out_ PNT_RING_BUFFER Ring, _In_ ULONG Capacity);

/*
 * RingBufDestroy — free NonPagedPool memory.
 * Call from DriverUnload (IRQL == PASSIVE_LEVEL).
 */
VOID RingBufDestroy(_In_ PNT_RING_BUFFER Ring);

/*
 * RingBufWrite — copy one event into the ring buffer.
 * Safe to call at IRQL <= DISPATCH_LEVEL (acquires spinlock).
 * Returns FALSE if the ring is full (event is dropped).
 */
BOOLEAN RingBufWrite(_In_ PNT_RING_BUFFER Ring, _In_ const NT_EVENT_RECORD *Event);

/*
 * RingBufReadBatch — drain up to MaxCount events into OutBuf.
 * Call at IRQL == PASSIVE_LEVEL (from IOCTL dispatch).
 * Returns the number of events actually copied.
 */
ULONG RingBufReadBatch(
    _In_  PNT_RING_BUFFER  Ring,
    _Out_ PNT_EVENT_RECORD OutBuf,
    _In_  ULONG            MaxCount);

/*
 * RingBufGetStats — fill an NT_STATS struct.
 */
VOID RingBufGetStats(_In_ PNT_RING_BUFFER Ring, _Out_ PNT_STATS Stats);
