/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Mullvad AB. All Rights Reserved.
 *
 * DAITA - Defence Against AI-Guided Traffic Analysis
 */

#pragma once

#include "daita.h"
#include <stddef.h>

#define LOG_DAITA_PREFIX "wireguard-daita: "
#include "logging.h"

/* mostly copied from logging.h, but with different prefix for tracing */
#if DBG
#    define LogDaitaErr(Device, Fmt, ...) \
        do \
        { \
            DbgPrintEx( \
                DPFLTR_IHVNETWORK_ID, \
                1, \
                LOG_DAITA_PREFIX LOG_DEVICE_PREFIX Fmt "\n", \
                (Device)->InterfaceIndex, \
                ##__VA_ARGS__); \
            LogRingWrite(&(Device)->Log, "1" Fmt, ##__VA_ARGS__); \
        } while (0)
#    define LogDaitaWarn(Device, Fmt, ...) \
        do \
        { \
            DbgPrintEx( \
                DPFLTR_IHVNETWORK_ID, \
                2, \
                LOG_DAITA_PREFIX LOG_DEVICE_PREFIX Fmt "\n", \
                (Device)->InterfaceIndex, \
                ##__VA_ARGS__); \
            LogRingWrite(&(Device)->Log, "2" Fmt, ##__VA_ARGS__); \
        } while (0)
#    define LogDaitaInfo(Device, Fmt, ...) \
        do \
        { \
            DbgPrintEx( \
                DPFLTR_IHVNETWORK_ID, \
                3, \
                LOG_DAITA_PREFIX LOG_DEVICE_PREFIX Fmt "\n", \
                (Device)->InterfaceIndex, \
                ##__VA_ARGS__); \
            LogRingWrite(&(Device)->Log, "3" Fmt, ##__VA_ARGS__); \
        } while (0)
#    define LogDaitaDebug(Fmt, ...) DbgPrintEx(DPFLTR_IHVNETWORK_ID, 4, LOG_DAITA_PREFIX Fmt "\n", ##__VA_ARGS__)
#else
#    define LogDaitaErr(Device, Fmt, ...) LogRingWrite(&(Device)->Log, "1" Fmt, ##__VA_ARGS__)
#    define LogDaitaWarn(Device, Fmt, ...) LogRingWrite(&(Device)->Log, "2" Fmt, ##__VA_ARGS__)
#    define LogDaitaInfo(Device, Fmt, ...) LogRingWrite(&(Device)->Log, "3" Fmt, ##__VA_ARGS__)
#    define LogDaitaDebug(Fmt, ...)
#endif

#define LogDaitaInfoRatelimited(Device, Fmt, ...) \
    do \
    { \
        if (!LogRingIsRatelimited(&(Device)->Log)) \
            LogDaitaInfo(Device, Fmt, ##__VA_ARGS__); \
    } while (0)

#define LogDaitaInfoNblRatelimited(Device, Fmt, Nbl, ...) \
    do \
    { \
        ENDPOINT __Endpoint; \
        CHAR __EndpointStr[SOCKADDR_STR_MAX_LEN]; \
        SocketEndpointFromNbl(&__Endpoint, Nbl); \
        SockaddrToString(__EndpointStr, &__Endpoint.Addr); \
        LogDaitaInfoRatelimited(Device, Fmt, __EndpointStr, ##__VA_ARGS__); \
    } while (0)

typedef struct _DAITA_SESSION_INTERNAL
{
    BOOLEAN Enabled;
    struct
    {
        /* number of elements contained in the ring */
        SIZE_T Capacity;
        DAITA_EVENT_RING *Ring;
        KEVENT *DataAvailable;
        MDL *Mdl;
        ULONG WriteOffset;
        KSPIN_LOCK Lock;
    } Event;
    struct
    {
        /* number of elements contained in the ring */
        SIZE_T Capacity;
        DAITA_ACTION_RING *Ring;
        KEVENT *DataAvailable;
        MDL *Mdl;
        HANDLE HandlerThread;
    } Action;
    KEVENT QuitEvent;
} DAITA_SESSION_INTERNAL;

typedef struct _WG_DEVICE WG_DEVICE;

_IRQL_requires_max_(APC_LEVEL)
VOID
DaitaDriverEntry(_In_ DRIVER_OBJECT *DriverObject);

typedef struct _DAITA_PADDING
{
    UCHAR Tag;
    USHORT TotalLength;
} DAITA_PADDING;

typedef struct _WG_PEER WG_PEER;

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
DaitaNonpaddingReceived(_In_ WG_PEER *Peer, ULONG Length);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
DaitaNonpaddingSent(_In_ WG_PEER *Peer, ULONG Length);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
DaitaPaddingReceived(_In_ WG_PEER *Peer, ULONG Length);

VOID
DaitaClose(_Inout_ WG_DEVICE *Wg);

#define DAITA_PADDING_TAG 0xFF
