/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023 Mullvad VPN AB. All Rights Reserved.
 */

#include "../driver/daita.h"
#include "adapter.h"
#include "wireguard.h"
#include "logger.h"
#include <Windows.h>

#define LOCK_SPIN_COUNT 0x10000

typedef struct _DAITA_SESSION_UM
{
    DAITA_SESSION Session;

    struct
    {
        CRITICAL_SECTION Lock;
    } Event, Action;
} DAITA_SESSION_UM;

WIREGUARD_DAITA_ACTIVATE_FUNC WireGuardDaitaActivate;
_Use_decl_annotations_
BOOL WINAPI
WireGuardDaitaActivate(WIREGUARD_ADAPTER *Adapter, SIZE_T EventsCapacity, SIZE_T ActionsCapacity)
{
    DWORD LastError;

    if (Adapter->DaitaSession)
    {
        return TRUE;
    }

    if (EventsCapacity == 0 || ActionsCapacity == 0)
    {
        LastError = ERROR_INVALID_PARAMETER;
        LOG(WIREGUARD_LOG_ERR, L"Capacities must be non-zero");
        goto cleanup;
    }

    DAITA_SESSION *Session = Zalloc(sizeof(DAITA_SESSION_UM));
    if (!Session)
    {
        LastError = GetLastError();
        LOG(WIREGUARD_LOG_ERR, L"Failed to allocate session: %d", LastError);
        goto cleanup;
    }

    const SIZE_T EventRingContainerSize = (sizeof(DAITA_EVENT) * EventsCapacity) + offsetof(DAITA_EVENT_RING, Events);
    const SIZE_T ActionRingContainerSize = (sizeof(DAITA_ACTION) * ActionsCapacity) + offsetof(DAITA_ACTION_RING, Actions);

    /* Allocate memory for ring buffers */
    BYTE *RingBuffers = VirtualAlloc(NULL, EventRingContainerSize + ActionRingContainerSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!RingBuffers)
    {
        LastError = GetLastError();
        LOG(WIREGUARD_LOG_ERR, L"Failed to allocate rings: %d", LastError);
        goto cleanupSession;
    }

    /* Populate session and create write event objects */
    Session->Event.Ring = (DAITA_EVENT_RING *)RingBuffers;
    Session->Event.DataAvailable = CreateEventW(&SecurityAttributes, FALSE, FALSE, NULL);
    Session->Event.Capacity = EventsCapacity;

    if (!Session->Event.DataAvailable)
    {
        LastError = GetLastError();
        LOG(WIREGUARD_LOG_ERR, L"Failed to create event object: %d", LastError);
        goto cleanupRingBuffers;
    }

    Session->Action.Ring = (DAITA_ACTION_RING *)(RingBuffers + EventRingContainerSize);
    Session->Action.DataAvailable = CreateEventW(&SecurityAttributes, FALSE, FALSE, NULL);
    Session->Action.Capacity = ActionsCapacity;

    if (!Session->Action.DataAvailable)
    {
        LastError = GetLastError();
        LOG(WIREGUARD_LOG_ERR, L"Failed to create event object: %d", LastError);
        goto cleanupEventDataAvailable;
    }

    /* Share buffers with KM */
    HANDLE ControlFile = AdapterOpenDeviceObject(Adapter);
    if (ControlFile == INVALID_HANDLE_VALUE)
    {
        LastError = GetLastError();
        LOG(WIREGUARD_LOG_ERR, L"Failed to open device: %d", LastError);
        goto cleanupActionDataAvailable;
    }

    DWORD BytesReturned;
    if (!DeviceIoControl(
            ControlFile, DAITA_IOCTL_ACTIVATE, Session, sizeof(*Session), NULL, 0, &BytesReturned, NULL))
    {
        LastError = GetLastError();
        LOG(WIREGUARD_LOG_ERR, L"DAITA_IOCTL_ACTIVATE failed: %d", LastError);
        goto cleanupDeviceHandle;
    }

    LOG(WIREGUARD_LOG_INFO, L"WireGuardDaitaActivate() succeeded");

    /* initializing the locks always succeeds despite what the return type suggests */
    DAITA_SESSION_UM *InternalSession = (DAITA_SESSION_UM *)Session;
    (void)InitializeCriticalSectionAndSpinCount(&InternalSession->Action.Lock, LOCK_SPIN_COUNT);
    (void)InitializeCriticalSectionAndSpinCount(&InternalSession->Event.Lock, LOCK_SPIN_COUNT);

    CloseHandle(ControlFile);
    Adapter->DaitaSession = Session;

    return TRUE;

cleanupDeviceHandle:
    CloseHandle(ControlFile);
cleanupActionDataAvailable:
    CloseHandle(Session->Action.DataAvailable);
cleanupEventDataAvailable:
    CloseHandle(Session->Event.DataAvailable);
cleanupRingBuffers:
    /* Only one free call: Both rings are allocated at once */
    VirtualFree(RingBuffers, 0, MEM_RELEASE);
cleanupSession:
    Free(Session);
cleanup:
    SetLastError(LastError);
    return FALSE;
}

VOID WINAPI
FreeDaitaSession(DAITA_SESSION *Session)
{
    if (!Session)
    {
        return;
    }

    DAITA_SESSION_UM *UmSession = (DAITA_SESSION_UM *)Session;

    DeleteCriticalSection(&UmSession->Action.Lock);
    DeleteCriticalSection(&UmSession->Event.Lock);

    CloseHandle(Session->Action.DataAvailable);
    CloseHandle(Session->Event.DataAvailable);

    /* Only one free call: Both rings are allocated at once */
    VirtualFree(Session->Event.Ring, 0, MEM_RELEASE);

    Free(Session);
}

WIREGUARD_DAITA_EVENT_DATA_AVAILABLE_FUNC WireGuardDaitaEventDataAvailableEvent;
_Use_decl_annotations_
HANDLE WINAPI
WireGuardDaitaEventDataAvailableEvent(WIREGUARD_ADAPTER *Adapter)
{
    if (!Adapter || !Adapter->DaitaSession)
    {
        LOG(WIREGUARD_LOG_ERR, L"Missing device or DAITA session");
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    return Adapter->DaitaSession->Event.DataAvailable;
}

WIREGUARD_DAITA_RECEIVE_EVENTS_FUNC WireGuardDaitaReceiveEvents;
_Use_decl_annotations_
SIZE_T WINAPI
WireGuardDaitaReceiveEvents(WIREGUARD_ADAPTER *Adapter, DAITA_EVENT *Events)
{
    if (!Adapter || !Adapter->DaitaSession)
    {
        LOG(WIREGUARD_LOG_ERR, L"Missing device or DAITA session");
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    DAITA_SESSION_UM *Session = (DAITA_SESSION_UM*)Adapter->DaitaSession;

    EnterCriticalSection(&Session->Event.Lock);

    ULONG ReadOffset = ReadULongAcquire(&Session->Session.Event.Ring->ReadOffset);
    ULONG WriteOffset = ReadULongAcquire(&Session->Session.Event.Ring->WriteOffset);

    if (ReadOffset == WriteOffset)
    {
        /* buffer is empty */
        SetLastError(ERROR_NO_MORE_ITEMS);
        LeaveCriticalSection(&Session->Event.Lock);
        return 0;
    }

    SIZE_T EventsRead = 0;

    if (ReadOffset < WriteOffset)
    {
        /* read from offset ReadOffset to WriteOffset */
        memcpy(
            Events, Session->Session.Event.Ring->Events + ReadOffset, sizeof(DAITA_EVENT) * (WriteOffset - ReadOffset));

        EventsRead = WriteOffset - ReadOffset;
    }
    else
    {
        /* wraps: read from offset ReadOffset to end */
        memcpy(
            Events, Session->Session.Event.Ring->Events + ReadOffset,
            sizeof(DAITA_EVENT) * (Session->Session.Event.Capacity - ReadOffset));

        EventsRead += Session->Session.Event.Capacity - ReadOffset;

        /* read from offset 0 to WriteOffset */
        memcpy(Events + EventsRead, Session->Session.Event.Ring->Events, sizeof(DAITA_EVENT) * WriteOffset);

        EventsRead += WriteOffset;
    }

    WriteULongRelease(&Session->Session.Event.Ring->ReadOffset, WriteOffset);
    LeaveCriticalSection(&Session->Event.Lock);

    return EventsRead;
}

WIREGUARD_DAITA_SEND_ACTION_FUNC WireGuardDaitaSendAction;
_Use_decl_annotations_
BOOL WINAPI
WireGuardDaitaSendAction(WIREGUARD_ADAPTER *Adapter, const DAITA_ACTION *Action)
{
    if (!Adapter || !Adapter->DaitaSession)
    {
        LOG(WIREGUARD_LOG_ERR, L"Missing device or DAITA session");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    DAITA_SESSION_UM *Session = (DAITA_SESSION_UM*)Adapter->DaitaSession;

    EnterCriticalSection(&Session->Action.Lock);

    ULONG ReadOffset = ReadULongAcquire(&Session->Session.Action.Ring->ReadOffset);
    ULONG WriteOffset = ReadULongAcquire(&Session->Session.Action.Ring->WriteOffset);
    ULONG NewWriteOffset = (WriteOffset + 1) % Session->Session.Action.Capacity;

    if (NewWriteOffset == ReadOffset)
    {
        /* buffer is full */
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        LeaveCriticalSection(&Session->Action.Lock);
        return FALSE;
    }

    memcpy(Session->Session.Action.Ring->Actions + WriteOffset, Action, sizeof(*Action));

    WriteULongRelease(&Session->Session.Action.Ring->WriteOffset, NewWriteOffset);

    LeaveCriticalSection(&Session->Action.Lock);

    SetEvent(Session->Session.Action.DataAvailable);

    return TRUE;
}
