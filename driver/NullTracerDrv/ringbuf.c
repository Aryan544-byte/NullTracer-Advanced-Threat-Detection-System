/*
 * ringbuf.c — NullTracer Kernel Driver
 * ======================================
 * Implementation of the NonPagedPool-backed SPSC ring buffer.
 *
 * Synchronisation model:
 *   - Writers (callbacks, multiple CPUs) acquire g_Ring.Lock (KSPIN_LOCK)
 *     before modifying Head.  This serialises concurrent callbacks.
 *   - The single consumer (IOCTL dispatch thread, PASSIVE_LEVEL) also
 *     acquires the lock when advancing Tail so that the occupancy check
 *     inside RingBufWrite is consistent.
 *
 * Index arithmetic:
 *   head & mask  ==  head % capacity   (works because capacity is power-of-two)
 */

#include <wdm.h>
#include "ringbuf.h"

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

static ULONG _Occupancy(_In_ const NT_RING_BUFFER *Ring)
{
    /* Snapshot both indices under the assumption caller holds the lock */
    return (Ring->Head - Ring->Tail) & Ring->Mask;
}

/* --------------------------------------------------------------------------
 * RingBufInit
 * -------------------------------------------------------------------------- */
NTSTATUS RingBufInit(_Out_ PNT_RING_BUFFER Ring, _In_ ULONG Capacity)
{
    ASSERT(Capacity != 0 && (Capacity & (Capacity - 1)) == 0);  /* power-of-two */

    RtlZeroMemory(Ring, sizeof(*Ring));

    Ring->Slots = (NT_EVENT_RECORD *)ExAllocatePoolWithTag(
        NonPagedPool,
        Capacity * sizeof(NT_EVENT_RECORD),
        'crtN');                    /* 'NullTracer' tag reversed for readability */

    if (!Ring->Slots) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Ring->Slots, Capacity * sizeof(NT_EVENT_RECORD));

    Ring->Capacity      = Capacity;
    Ring->Mask          = Capacity - 1;
    Ring->Head          = 0;
    Ring->Tail          = 0;
    Ring->TotalProduced = 0;
    Ring->TotalConsumed = 0;
    Ring->TotalDropped  = 0;

    KeInitializeSpinLock(&Ring->Lock);

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * RingBufDestroy
 * -------------------------------------------------------------------------- */
VOID RingBufDestroy(_In_ PNT_RING_BUFFER Ring)
{
    if (Ring->Slots) {
        ExFreePoolWithTag(Ring->Slots, 'crtN');
        Ring->Slots = NULL;
    }
}

/* --------------------------------------------------------------------------
 * RingBufWrite — called from kernel callbacks (IRQL <= DISPATCH_LEVEL)
 * -------------------------------------------------------------------------- */
BOOLEAN RingBufWrite(_In_ PNT_RING_BUFFER Ring, _In_ const NT_EVENT_RECORD *Event)
{
    KIRQL   OldIrql;
    BOOLEAN Written = FALSE;

    KeAcquireSpinLock(&Ring->Lock, &OldIrql);

    if (_Occupancy(Ring) < Ring->Capacity - 1) {
        /* Slot at Head is free — copy the event in */
        RtlCopyMemory(
            &Ring->Slots[Ring->Head & Ring->Mask],
            Event,
            sizeof(NT_EVENT_RECORD));

        Ring->Head = (Ring->Head + 1) & (Ring->Capacity - 1 + 1);
        /* NOTE: Head/Tail are kept as plain incrementing counters (not masked)
         *       so that subtraction gives occupancy.  We keep them ULONG and
         *       let them wrap naturally — modulo 2^32.  Mask is applied only
         *       when indexing into Slots[]. */
        Ring->Head = Ring->Head;    /* explicit no-op: Head already incremented */

        Ring->TotalProduced++;
        Written = TRUE;
    } else {
        Ring->TotalDropped++;
    }

    KeReleaseSpinLock(&Ring->Lock, OldIrql);
    return Written;
}

/* --------------------------------------------------------------------------
 * RingBufReadBatch — called from IOCTL dispatch (IRQL == PASSIVE_LEVEL)
 * -------------------------------------------------------------------------- */
ULONG RingBufReadBatch(
    _In_  PNT_RING_BUFFER  Ring,
    _Out_ PNT_EVENT_RECORD OutBuf,
    _In_  ULONG            MaxCount)
{
    KIRQL OldIrql;
    ULONG Copied = 0;

    KeAcquireSpinLock(&Ring->Lock, &OldIrql);

    while (Copied < MaxCount && Ring->Tail != Ring->Head) {
        RtlCopyMemory(
            &OutBuf[Copied],
            &Ring->Slots[Ring->Tail & Ring->Mask],
            sizeof(NT_EVENT_RECORD));

        Ring->Tail = Ring->Tail + 1;
        Ring->TotalConsumed++;
        Copied++;
    }

    KeReleaseSpinLock(&Ring->Lock, OldIrql);
    return Copied;
}

/* --------------------------------------------------------------------------
 * RingBufGetStats
 * -------------------------------------------------------------------------- */
VOID RingBufGetStats(_In_ PNT_RING_BUFFER Ring, _Out_ PNT_STATS Stats)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&Ring->Lock, &OldIrql);

    Stats->TotalEventsProduced = Ring->TotalProduced;
    Stats->TotalEventsConsumed = Ring->TotalConsumed;
    Stats->TotalEventsDropped  = Ring->TotalDropped;
    Stats->RingCapacity        = Ring->Capacity;
    Stats->RingOccupancy       = (Ring->Head - Ring->Tail);

    KeReleaseSpinLock(&Ring->Lock, OldIrql);
}
