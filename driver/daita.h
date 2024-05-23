/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024 Mullvad AB. All Rights Reserved.
 *
 * DAITA - Defence Against AI-Guided Traffic Analysis
 */

#pragma once

#include "ioctl.h"
#include <stddef.h>

#pragma warning(push)
/* nonstandard extension: zero-sized array in struct/union */
#pragma warning(disable : 4200)

typedef enum _DAITA_EVENT_TYPE
{
    DAITA_EVENT_NONPADDING_SENT,
    DAITA_EVENT_NONPADDING_RECEIVED,
    DAITA_EVENT_PADDING_SENT,
    DAITA_EVENT_PADDING_RECEIVED
} DAITA_EVENT_TYPE;

typedef struct _DAITA_EVENT
{
    UINT8 Peer[WG_KEY_LEN];
    DAITA_EVENT_TYPE EventType;
    USHORT XmitBytes;
    /* arbitrary 'UserContext' data set for the action that triggered the events,
       0 when this is not relevant */
    SIZE_T UserContext;
} DAITA_EVENT;

typedef enum _DAITA_ACTION_TYPE
{
    DAITA_ACTION_TYPE_INJECT_PADDING
} DAITA_ACTION_TYPE;

typedef struct _DAITA_PADDING_ACTION
{
    USHORT ByteCount;
    BOOLEAN Replace;
} DAITA_PADDING_ACTION;

typedef struct _DAITA_ACTION
{
    UINT8 Peer[WG_KEY_LEN];
    DAITA_ACTION_TYPE ActionType;
    union
    {
        DAITA_PADDING_ACTION Padding;
    } Payload;
    /* arbitrary 'UserContext' to set in the event that is triggered by this action */
    SIZE_T UserContext;
} DAITA_ACTION;

typedef struct _DAITA_EVENT_RING
{
    /* must be volatile because the memory is shared between UM and KM */
    /* the offset is specified in *number of elements* */
    volatile ULONG ReadOffset;
    volatile ULONG WriteOffset;
    DAITA_EVENT Events[];
} DAITA_EVENT_RING;

typedef struct _DAITA_ACTION_RING
{
    /* must be volatile because the memory is shared between UM and KM */
    /* the offset is specified in *number of elements* */
    volatile ULONG ReadOffset;
    volatile ULONG WriteOffset;
    DAITA_ACTION Actions[];
} DAITA_ACTION_RING;

typedef struct _DAITA_SESSION
{
    struct
    {
        /* number of elements contained in the ring */
        SIZE_T Capacity;
        DAITA_EVENT_RING *Ring;
        HANDLE DataAvailable;
    } Event;
    struct
    {
        /* number of elements contained in the ring */
        SIZE_T Capacity;
        DAITA_ACTION_RING *Ring;
        HANDLE DataAvailable;
    } Action;
} DAITA_SESSION;

/* Associate ring buffers with a WG device. */
#define DAITA_IOCTL_ACTIVATE CTL_CODE(45208U, 325, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#pragma warning(pop)
