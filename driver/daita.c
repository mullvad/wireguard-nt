/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Mullvad AB. All Rights Reserved.
 *
 * DAITA - Defence Against AI-Guided Traffic Analysis
 */

#include "daita_internal.h"
#include "device.h"
#include "peer.h"
#include "queueing.h"
#include <ntddk.h>

static DRIVER_DISPATCH *NdisDispatchDeviceControl;

static inline VOID
CopyPubkey(
    _Out_writes_bytes_all_(NOISE_PUBLIC_KEY_LEN) UINT8 *Buffer,
    _In_reads_bytes_(NOISE_PUBLIC_KEY_LEN) const WG_PEER *Peer)
{
    RtlCopyMemory(Buffer, Peer->Handshake.RemoteStatic, NOISE_PUBLIC_KEY_LEN);
}

static inline BOOLEAN
EqualPubkeys(
    _In_reads_bytes_(NOISE_PUBLIC_KEY_LEN) const UINT8 *Key1,
    _In_reads_bytes_(NOISE_PUBLIC_KEY_LEN) const UINT8 *Key2)
{
    return RtlCompareMemory(Key1, Key2, NOISE_PUBLIC_KEY_LEN) == NOISE_PUBLIC_KEY_LEN;
}

/* Find a free element in the event ring buffer and use FillEvent to fill it before updating the write
   pointer. This is a silent no-op if the ring buffer is full. */
_Requires_lock_not_held_(Peer->Device->Daita.Event.Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
DaitaEmitEvent(
    _In_ WG_PEER *Peer,
    _In_ DAITA_EVENT_TYPE EventType,
    _In_ USHORT XmitBytes,
    _In_ SIZE_T UserContext)
{
    if (!Peer->Device || !ReadBooleanNoFence(&Peer->Device->Daita.Enabled))
    {
        return;
    }

    DAITA_SESSION_INTERNAL *Daita = &Peer->Device->Daita;

    ULONG ReadOffset = ReadULongAcquire(&Daita->Event.Ring->ReadOffset) % Daita->Event.Capacity;

    KIRQL OldIrql;
    KeAcquireSpinLock(&Daita->Event.Lock, &OldIrql);

    ULONG WriteOffset = ReadULongAcquire(&Daita->Event.WriteOffset);
    ULONG NewWriteOffset = (WriteOffset + 1) % Daita->Event.Capacity;

    if (NewWriteOffset == ReadOffset)
    {
        goto releaseLockFull;
    }

    /* Fill in event details */
    DAITA_EVENT *NewEvent = &Daita->Event.Ring->Events[WriteOffset];
    NewEvent->EventType = EventType;
    NewEvent->XmitBytes = XmitBytes;
    NewEvent->UserContext = UserContext;
    CopyPubkey(NewEvent->Peer, Peer);

    WriteULongRelease(&Daita->Event.WriteOffset, NewWriteOffset);

    /* Bump shared write pointer and signal write event */
    WriteULongRelease(&Daita->Event.Ring->WriteOffset, NewWriteOffset);

    KeReleaseSpinLock(&Daita->Event.Lock, OldIrql);

    KeSetEvent(Daita->Event.DataAvailable, IO_NETWORK_INCREMENT, FALSE);
    return;

releaseLockFull:

    KeReleaseSpinLock(&Daita->Event.Lock, OldIrql);

    LogDaitaInfoRatelimited(Peer->Device, "Dropping DAITA event (type %u) since event buffer is full", EventType);
}

_Use_decl_annotations_
VOID
DaitaNonpaddingReceived(_In_ WG_PEER *Peer, ULONG Length)
{
    /*LogDaitaDebug("Nonpadding recv: %lu", Length);*/
    DaitaEmitEvent(Peer, DAITA_EVENT_NONPADDING_RECEIVED, (USHORT) Length, 0);
}

_Use_decl_annotations_
VOID
DaitaNonpaddingSent(_In_ WG_PEER *Peer, ULONG Length)
{
    /*LogDaitaDebug("Nonpadding sent: %lu", Length);*/
    DaitaEmitEvent(Peer, DAITA_EVENT_NONPADDING_SENT, (USHORT) Length, 0);
}

_Use_decl_annotations_
VOID
DaitaPaddingReceived(_In_ WG_PEER *Peer, ULONG Length)
{
    LogDaitaDebug("Padding recv: %lu", Length);
    DaitaEmitEvent(Peer, DAITA_EVENT_PADDING_RECEIVED, (USHORT)Length, 0);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
DaitaPaddingSent(_In_ WG_PEER *Peer, ULONG Length, SIZE_T UserContext)
{
    LogDaitaDebug("Padding sent: %lu", Length);
    DaitaEmitEvent(Peer, DAITA_EVENT_PADDING_SENT, (USHORT)Length, UserContext);
}

/* Return whether a packet is already queued. This includes padding packets. */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(Peer->StagedPacketQueue.Lock)
static BOOLEAN
HasPacketQueued(_In_ WG_PEER *Peer, ULONG HeaderLength)
{
    KIRQL Irql;
    KeAcquireSpinLock(&Peer->StagedPacketQueue.Lock, &Irql);

    for (PNET_BUFFER_LIST Nbl = Peer->StagedPacketQueue.Head; Nbl; Nbl = NET_BUFFER_LIST_NEXT_NBL(Nbl))
    {
        for (NET_BUFFER *NbIn = NET_BUFFER_LIST_FIRST_NB(Nbl->ParentNetBufferList); NbIn;
             NbIn = NET_BUFFER_NEXT_NB(NbIn))
        {
            if (Nbl != Nbl->ParentNetBufferList)
            {
                continue;
            }

            /* Padding packets are pre-padded, so check the actual padding header */
            if (NET_BUFFER_DATA_LENGTH(NbIn) >= sizeof(DAITA_PADDING) + sizeof(MESSAGE_DATA))
            {
                DAITA_PADDING *Padding =
                    (DAITA_PADDING *)((BYTE *)MemGetValidatedNetBufferData(NbIn) + sizeof(MESSAGE_DATA));
                if (Padding->Tag == DAITA_PADDING_TAG && Ntohs(Padding->TotalLength) == HeaderLength)
                {
                    goto foundPacket;
                }
            }
        }
    }
    KeReleaseSpinLock(&Peer->StagedPacketQueue.Lock, Irql);
    return FALSE;

foundPacket:
    KeReleaseSpinLock(&Peer->StagedPacketQueue.Lock, Irql);
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
SendPaddingPacket(_Inout_ WG_PEER *Peer, USHORT PaddingSize, BOOLEAN Replace, SIZE_T UserContext)
{
    if (!ReadBooleanNoFence(&Peer->Device->IsUp))
    {
        return;
    }

    ADDRESS_FAMILY Family = ReadUShortNoFence(&Peer->Endpoint.Addr.si_family);
    ULONG Mtu;

    if (Family == AF_INET)
    {
        Mtu = Peer->Device->Mtu4;
    }
    else if (Family == AF_INET6)
    {
        Mtu = Peer->Device->Mtu6;
    }
    else
    {
        LogDaitaInfo(Peer->Device, "Ignoring DAITA peer %llu without a valid endpoint", Peer->InternalId);
        return;
    }

    if (PaddingSize < sizeof(DAITA_PADDING) || PaddingSize > Mtu)
    {
        return;
    }

    if (Replace && HasPacketQueued(Peer, PaddingSize))
    {
        LogDaitaInfoRatelimited(Peer->Device, "Dropping padding event since there's a packet queued");

        /* NOTE: We're sending a padding event even if it's replaced here. */
        DaitaEmitEvent(Peer, DAITA_EVENT_PADDING_SENT, PaddingSize, UserContext);
        return;
    }

    ULONG ActualPaddingSize = Peer->ConstantPacketSize ? Mtu : PaddingSize;
    NET_BUFFER_LIST *Nbl = MemAllocateNetBufferList(sizeof(MESSAGE_DATA), ActualPaddingSize, NoiseEncryptedLen(0));
    if (!Nbl)
    {
        LogDaitaWarn(Peer->Device, "Dropping padding packet: could not alloc NBL");
        return;
    }

    /* use same NBL for encrypted output */
    Nbl->ParentNetBufferList = Nbl;

    DAITA_PADDING *Padding = (DAITA_PADDING *)((BYTE *)MemGetValidatedNetBufferListData(Nbl) + sizeof(MESSAGE_DATA));
    RtlZeroMemory(Padding, PaddingSize);
    Padding->Tag = DAITA_PADDING_TAG;
    Padding->TotalLength = Htons(PaddingSize);

    NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_SUCCESS;

    NetBufferListInterlockedEnqueue(&Peer->StagedPacketQueue, Nbl);

    DaitaPaddingSent(Peer, PaddingSize, UserContext);

    PacketSendStagedPackets(Peer);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(KSTART_ROUTINE)
static VOID
HandleDaitaActions(_Inout_ VOID *Ctx)
{
    NTSTATUS Status = STATUS_SUCCESS;
    WG_DEVICE *Wg = (WG_DEVICE *)Ctx;

    /* This thread controls the action read pointer */
    ULONG ReadOffset = 0;

    KEVENT *EventObjects[] = { &Wg->Daita.QuitEvent, & Wg->DeviceRemoved, Wg->Daita.Action.DataAvailable };

    for (; !KeReadStateEvent(&Wg->DeviceRemoved) && !KeReadStateEvent(&Wg->Daita.QuitEvent); )
    {
        const NTSTATUS WaitResult = KeWaitForMultipleObjects(
            RTL_NUMBER_OF(EventObjects), EventObjects, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);

        if (!NT_SUCCESS(WaitResult))
        {
            LogDaitaErr(Wg, "WaitForMultipleObjects() failed: %d", WaitResult);
            Status = WaitResult;
            break;
        }
        if (WaitResult == STATUS_WAIT_0)
        {
            continue;
        }

        const ULONG WriteOffset = ReadULongAcquire(&Wg->Daita.Action.Ring->WriteOffset) % Wg->Daita.Action.Capacity;

        if (ReadOffset == WriteOffset)
        {
            continue;
        }

        /* Now we process all actions from "read" onwards */
        while (ReadOffset != WriteOffset)
        {
            DAITA_ACTION *Action = &Wg->Daita.Action.Ring->Actions[ReadOffset];

            switch (Action->ActionType)
            {
            case DAITA_ACTION_TYPE_INJECT_PADDING: {
                WG_PEER *Peer;

                MuAcquirePushLockExclusive(&Wg->DeviceUpdateLock);
                LIST_FOR_EACH_ENTRY (Peer, &Wg->PeerList, WG_PEER, PeerList)
                {
                    if (EqualPubkeys(Peer->Handshake.RemoteStatic, Action->Peer))
                    {
                        SendPaddingPacket(
                            Peer,
                            Action->Payload.Padding.ByteCount,
                            Action->Payload.Padding.Replace,
                            Action->UserContext);
                    }
                }
                MuReleasePushLockExclusive(&Wg->DeviceUpdateLock);
                break;
            }

            default:
                LogDaitaErr(Wg, "Ignoring unknown DAITA action type");
                break;
            }

            ReadOffset = (ReadOffset + 1) % Wg->Daita.Action.Capacity;
        }

        /* Update shared read pointer */
        WriteULongRelease(&Wg->Daita.Action.Ring->ReadOffset, ReadOffset);
    }
    LogDaitaInfo(Wg, "Stopping DAITA action thread");
    PsTerminateSystemThread(Status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
DaitaActivate(_In_ DEVICE_OBJECT *DeviceObject, _Inout_ IRP *Irp)
{
    NTSTATUS Status = STATUS_SUCCESS;

    Irp->IoStatus.Information = 0;

    if (!HasAccess(FILE_WRITE_DATA, Irp->RequestorMode, &Status))
        goto cleanup;

    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    if (Stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(DAITA_SESSION))
    {
        Status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    DAITA_SESSION Session;
    RtlCopyMemory(&Session, Irp->AssociatedIrp.SystemBuffer, sizeof(DAITA_SESSION));

    if (Session.Action.Capacity == 0 || Session.Event.Capacity == 0 ||
        sizeof(DAITA_EVENT) * Session.Event.Capacity > ULONG_MAX ||
        sizeof(DAITA_ACTION) * Session.Action.Capacity > ULONG_MAX)
    {
        /* invalid action or event buffer size */
        Status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    WG_DEVICE *Wg = DeviceObject->Reserved;
    if (!Wg || ReadBooleanNoFence(&Wg->IsDeviceRemoving))
    {
        Status = NDIS_STATUS_ADAPTER_REMOVED;
        goto cleanup;
    }

    if (ReadBooleanNoFence(&Wg->Daita.Enabled))
    {
        /* session already exists */
        Status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    WriteBooleanNoFence(&Wg->Daita.Enabled, TRUE);

    /*
     * Map event buffer to system virtual mem space
     */

    Wg->Daita.Event.Mdl = IoAllocateMdl(Session.Event.Ring, (ULONG)(sizeof(DAITA_EVENT) * Session.Event.Capacity), FALSE, FALSE, NULL);
    if (!Wg->Daita.Event.Mdl)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanupContext;
    }

    try
    {
        MmProbeAndLockPages(Wg->Daita.Event.Mdl, Irp->RequestorMode, IoWriteAccess);
    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = STATUS_INVALID_USER_BUFFER;
        goto cleanupEventMdl;
    }

    Wg->Daita.Event.Ring = MmGetSystemAddressForMdlSafe(Wg->Daita.Event.Mdl, NormalPagePriority | MdlMappingNoExecute);
    if (!Wg->Daita.Event.Ring)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanupEventUnlockPages;
    }
    Wg->Daita.Event.Capacity = Session.Event.Capacity;

    /* Get KM handle for event object */
    if (!NT_SUCCESS(
            Status = ObReferenceObjectByHandle(
                Session.Event.DataAvailable,
                EVENT_MODIFY_STATE,
                *ExEventObjectType,
                Irp->RequestorMode,
                &Wg->Daita.Event.DataAvailable,
                NULL)))
    {
        goto cleanupEventUnlockPages;
    }

    /*
     * Map action buffer to system virtual mem space
     */

    Wg->Daita.Action.Mdl = IoAllocateMdl(Session.Action.Ring, (ULONG)(sizeof(DAITA_ACTION) * Session.Action.Capacity), FALSE, FALSE, NULL);
    if (!Wg->Daita.Action.Mdl)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanupEventMoveEvent;
    }

    try
    {
        MmProbeAndLockPages(Wg->Daita.Action.Mdl, Irp->RequestorMode, IoWriteAccess);
    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = STATUS_INVALID_USER_BUFFER;
        goto cleanupActionMdl;
    }

    Wg->Daita.Action.Ring =
        MmGetSystemAddressForMdlSafe(Wg->Daita.Action.Mdl, NormalPagePriority | MdlMappingNoExecute);
    if (!Wg->Daita.Action.Ring)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanupActionUnlockPages;
    }
    Wg->Daita.Action.Capacity = Session.Action.Capacity;

    /* Get KM handle for event object */
    if (!NT_SUCCESS(
            Status = ObReferenceObjectByHandle(
                Session.Action.DataAvailable,
                /* SYNCHRONIZE is needed to wait on signal from UM */
                SYNCHRONIZE | EVENT_MODIFY_STATE,
                *ExEventObjectType,
                Irp->RequestorMode,
                &Wg->Daita.Action.DataAvailable,
                NULL)))
    {
        goto cleanupActionUnlockPages;
    }

    /* Start DAITA action handler thread */
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    KeInitializeEvent(&Wg->Daita.QuitEvent, NotificationEvent, FALSE);

    if (!NT_SUCCESS(PsCreateSystemThread(
            &Wg->Daita.Action.HandlerThread,
            THREAD_ALL_ACCESS,
            &ObjectAttributes,
            NULL,
            NULL,
            HandleDaitaActions,
            DeviceObject->Reserved)))
    {
        goto cleanupActionMoveEvent;
    }

    KeInitializeSpinLock(&Wg->Daita.Event.Lock);

    Irp->IoStatus.Status = STATUS_SUCCESS;

    return;

cleanupActionMoveEvent:
    ObDereferenceObject(Wg->Daita.Action.DataAvailable);
cleanupActionUnlockPages:
    MmUnlockPages(Wg->Daita.Action.Mdl);
cleanupActionMdl:
    IoFreeMdl(Wg->Daita.Action.Mdl);
cleanupEventMoveEvent:
    ObDereferenceObject(Wg->Daita.Event.DataAvailable);
cleanupEventUnlockPages:
    MmUnlockPages(Wg->Daita.Event.Mdl);
cleanupEventMdl:
    IoFreeMdl(Wg->Daita.Event.Mdl);
cleanupContext:
    RtlZeroMemory(&Wg->Daita, sizeof(Wg->Daita));
    /* Wg->Daita.Exists = FALSE; */
cleanup:
    Irp->IoStatus.Status = Status;
}

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
static DRIVER_DISPATCH_PAGED DispatchDeviceControl;
_Use_decl_annotations_
static NTSTATUS
DispatchDeviceControl(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    switch (Stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case DAITA_IOCTL_ACTIVATE:
        DaitaActivate(DeviceObject, Irp);
        break;
    default:
        return NdisDispatchDeviceControl(DeviceObject, Irp);
    }
    NTSTATUS Status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

VOID
DaitaClose(_Inout_ WG_DEVICE *Wg)
{
    if (!ReadBooleanNoFence(&Wg->Daita.Enabled))
        return;

    LogDaitaInfo(Wg, "Destroying DAITA context");

    KeSetEvent(&Wg->Daita.QuitEvent, IO_NETWORK_INCREMENT, FALSE);

    /* Kill action thread */
    PKTHREAD Thread;
    if (NT_SUCCESS(ObReferenceObjectByHandle(Wg->Daita.Action.HandlerThread, SYNCHRONIZE, NULL, KernelMode, &Thread, NULL)))
    {
        KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, NULL);
        ObfDereferenceObject(Thread);
    }
    ZwClose(Wg->Daita.Action.HandlerThread);

    MmUnlockPages(Wg->Daita.Action.Mdl);
    IoFreeMdl(Wg->Daita.Action.Mdl);
    ObDereferenceObject(Wg->Daita.Action.DataAvailable);

    MmUnlockPages(Wg->Daita.Event.Mdl);
    IoFreeMdl(Wg->Daita.Event.Mdl);
    ObDereferenceObject(Wg->Daita.Event.DataAvailable);

    WriteBooleanNoFence(&Wg->Daita.Enabled, FALSE);
    RtlZeroMemory(&Wg->Daita, sizeof(Wg->Daita));
}

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, DaitaDriverEntry)
#endif
_Use_decl_annotations_
VOID
DaitaDriverEntry(DRIVER_OBJECT *DriverObject)
{
    NdisDispatchDeviceControl = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
}
