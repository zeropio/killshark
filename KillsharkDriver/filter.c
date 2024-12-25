/*++

Copyright (c) Microsoft Corporation

Module Name:

    Filter.c
--*/

#include "precomp.h"

#define CustomNtohl(x) (((x & 0xFF) << 24) | \
                       ((x & 0xFF00) << 8) | \
                       ((x & 0xFF0000) >> 8) | \
                       ((x >> 24) & 0xFF))

#define __FILENUMBER    'PNPF'

#pragma NDIS_INIT_FUNCTION(DriverEntry)

// Global variables
NDIS_HANDLE         FilterDriverHandle; // NDIS handle for filter driver
NDIS_HANDLE         FilterDriverObject;
NDIS_HANDLE         NdisFilterDeviceHandle = NULL;
PDEVICE_OBJECT      NdisDeviceObject = NULL;

FILTER_LOCK         FilterListLock;
LIST_ENTRY          FilterModuleList;

NDIS_FILTER_PARTIAL_CHARACTERISTICS DefaultChars = {
{ 0, 0, 0},
      0,
      NULL,
      NULL,
      NULL,
      FilterReceiveNetBufferLists,
      NULL
};


_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT      DriverObject,
    PUNICODE_STRING     RegistryPath
    )
{
    NDIS_STATUS Status;
    NDIS_FILTER_DRIVER_CHARACTERISTICS      FChars;
    NDIS_STRING ServiceName  = RTL_CONSTANT_STRING(FILTER_SERVICE_NAME);
    NDIS_STRING UniqueName   = RTL_CONSTANT_STRING(FILTER_UNIQUE_NAME);
    NDIS_STRING FriendlyName = RTL_CONSTANT_STRING(FILTER_FRIENDLY_NAME);
    BOOLEAN bFalse = FALSE;

    UNREFERENCED_PARAMETER(RegistryPath);

    DEBUGP(DL_TRACE, "===>DriverEntry...\n");
    KdPrint(("===> DriverEntry...\n"));

    FilterDriverObject = DriverObject;

    do
    {
        NdisZeroMemory(&FChars, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));
        FChars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
        FChars.Header.Size = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);
#if NDIS_SUPPORT_NDIS61
        FChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
#else
        FChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_1;
#endif

        FChars.MajorNdisVersion = FILTER_MAJOR_NDIS_VERSION;
        FChars.MinorNdisVersion = FILTER_MINOR_NDIS_VERSION;
        FChars.MajorDriverVersion = 1;
        FChars.MinorDriverVersion = 0;
        FChars.Flags = 0;

        FChars.FriendlyName = FriendlyName;
        FChars.UniqueName = UniqueName;
        FChars.ServiceName = ServiceName;

        FChars.SetOptionsHandler = FilterRegisterOptions;
        FChars.AttachHandler = FilterAttach;
        FChars.DetachHandler = FilterDetach;
        FChars.RestartHandler = FilterRestart;
        FChars.PauseHandler = FilterPause;

        FChars.SendNetBufferListsHandler = NULL;
        FChars.ReturnNetBufferListsHandler = NULL;
        FChars.SendNetBufferListsCompleteHandler = NULL;
        FChars.ReceiveNetBufferListsHandler = FilterReceiveNetBufferLists;
        FChars.CancelSendNetBufferListsHandler = NULL;

        // Optional handlers set to NULL
        FChars.SetFilterModuleOptionsHandler = NULL;
        FChars.OidRequestHandler = NULL;
        FChars.OidRequestCompleteHandler = NULL;
        FChars.CancelOidRequestHandler = NULL;
        FChars.DevicePnPEventNotifyHandler = NULL;
        FChars.NetPnPEventHandler = NULL;
        FChars.StatusHandler = NULL;

        DriverObject->DriverUnload = FilterUnload;

        FilterDriverHandle = NULL;

        // Initialize spin locks
        FILTER_INIT_LOCK(&FilterListLock);

        InitializeListHead(&FilterModuleList);

        Status = NdisFRegisterFilterDriver(DriverObject,
                                           (NDIS_HANDLE)FilterDriverObject,
                                           &FChars,
                                           &FilterDriverHandle);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DEBUGP(DL_WARN, "Register filter driver failed.\n");
            break;
        }

        Status = FilterRegisterDevice();

        if (Status != NDIS_STATUS_SUCCESS)
        {
            NdisFDeregisterFilterDriver(FilterDriverHandle);
            FILTER_FREE_LOCK(&FilterListLock);
            DEBUGP(DL_WARN, "Register device for the filter driver failed.\n");
            break;
        }


    }
    while(bFalse);


    DEBUGP(DL_TRACE, "<===DriverEntry, Status = %8x\n", Status);
    return Status;

}

_Use_decl_annotations_
NDIS_STATUS
FilterRegisterOptions(
    NDIS_HANDLE  NdisFilterDriverHandle,
    NDIS_HANDLE  FilterDriverContext
    )
{
    DEBUGP(DL_TRACE, "===>FilterRegisterOptions\n");

    ASSERT(NdisFilterDriverHandle == FilterDriverHandle);
    ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);

    if ((NdisFilterDriverHandle != (NDIS_HANDLE)FilterDriverHandle) ||
        (FilterDriverContext != (NDIS_HANDLE)FilterDriverObject))
    {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    DEBUGP(DL_TRACE, "<===FilterRegisterOptions\n");

    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
NDIS_STATUS
FilterAttach(
    NDIS_HANDLE                     NdisFilterHandle,
    NDIS_HANDLE                     FilterDriverContext,
    PNDIS_FILTER_ATTACH_PARAMETERS  AttachParameters
    )
{
    PMS_FILTER              pFilter = NULL;
    NDIS_STATUS             Status = NDIS_STATUS_SUCCESS;
    NDIS_FILTER_ATTRIBUTES  FilterAttributes;
    ULONG                   Size;
    BOOLEAN               bFalse = FALSE;

    DEBUGP(DL_TRACE, "===>FilterAttach: NdisFilterHandle %p\n", NdisFilterHandle);

    do
    {
        ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);
        if (FilterDriverContext != (NDIS_HANDLE)FilterDriverObject)
        {
            Status = NDIS_STATUS_INVALID_PARAMETER;
            break;
        }

        if ((AttachParameters->MiniportMediaType != NdisMedium802_3)
                && (AttachParameters->MiniportMediaType != NdisMediumWan)
                && (AttachParameters->MiniportMediaType != NdisMediumWirelessWan))
        {
           DEBUGP(DL_ERROR, "Unsupported media type.\n");

           Status = NDIS_STATUS_INVALID_PARAMETER;
           break;
        }

        Size = sizeof(MS_FILTER) +
               AttachParameters->FilterModuleGuidName->Length +
               AttachParameters->BaseMiniportInstanceName->Length +
               AttachParameters->BaseMiniportName->Length;

        pFilter = (PMS_FILTER)FILTER_ALLOC_MEM(NdisFilterHandle, Size);
        if (pFilter == NULL)
        {
            DEBUGP(DL_WARN, "Failed to allocate context structure.\n");
            Status = NDIS_STATUS_RESOURCES;
            break;
        }

        NdisZeroMemory(pFilter, sizeof(MS_FILTER));

        pFilter->FilterModuleName.Length = pFilter->FilterModuleName.MaximumLength = AttachParameters->FilterModuleGuidName->Length;
        pFilter->FilterModuleName.Buffer = (PWSTR)((PUCHAR)pFilter + sizeof(MS_FILTER));
        NdisMoveMemory(pFilter->FilterModuleName.Buffer,
                        AttachParameters->FilterModuleGuidName->Buffer,
                        pFilter->FilterModuleName.Length);



        pFilter->MiniportFriendlyName.Length = pFilter->MiniportFriendlyName.MaximumLength = AttachParameters->BaseMiniportInstanceName->Length;
        pFilter->MiniportFriendlyName.Buffer = (PWSTR)((PUCHAR)pFilter->FilterModuleName.Buffer + pFilter->FilterModuleName.Length);
        NdisMoveMemory(pFilter->MiniportFriendlyName.Buffer,
                        AttachParameters->BaseMiniportInstanceName->Buffer,
                        pFilter->MiniportFriendlyName.Length);


        pFilter->MiniportName.Length = pFilter->MiniportName.MaximumLength = AttachParameters->BaseMiniportName->Length;
        pFilter->MiniportName.Buffer = (PWSTR)((PUCHAR)pFilter->MiniportFriendlyName.Buffer +
                                                   pFilter->MiniportFriendlyName.Length);
        NdisMoveMemory(pFilter->MiniportName.Buffer,
                        AttachParameters->BaseMiniportName->Buffer,
                        pFilter->MiniportName.Length);

        pFilter->MiniportIfIndex = AttachParameters->BaseMiniportIfIndex;

        pFilter->TrackReceives = TRUE;
        pFilter->TrackSends = TRUE;
        pFilter->FilterHandle = NdisFilterHandle;


        NdisZeroMemory(&FilterAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));
        FilterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
        FilterAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
        FilterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
        FilterAttributes.Flags = 0;

        NDIS_DECLARE_FILTER_MODULE_CONTEXT(MS_FILTER);
        Status = NdisFSetAttributes(NdisFilterHandle,
                                    pFilter,
                                    &FilterAttributes);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DEBUGP(DL_WARN, "Failed to set attributes.\n");
            break;
        }


        pFilter->State = FilterPaused;

        FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
        InsertHeadList(&FilterModuleList, &pFilter->FilterModuleLink);
        FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

    }
    while (bFalse);

    if (Status != NDIS_STATUS_SUCCESS)
    {
        if (pFilter != NULL)
        {
            FILTER_FREE_MEM(pFilter);
        }
    }

    DEBUGP(DL_TRACE, "<===FilterAttach:    Status %x\n", Status);
    return Status;
}

_Use_decl_annotations_
NDIS_STATUS
FilterPause(
    NDIS_HANDLE                     FilterModuleContext,
    PNDIS_FILTER_PAUSE_PARAMETERS   PauseParameters
    )
{
    PMS_FILTER          pFilter = (PMS_FILTER)(FilterModuleContext);
    NDIS_STATUS         Status;
    BOOLEAN               bFalse = FALSE;

    UNREFERENCED_PARAMETER(PauseParameters);

    DEBUGP(DL_TRACE, "===>KILLSHARK FilterPause: FilterInstance %p\n", FilterModuleContext);

    // Set the flag that the filter is going to pause
    FILTER_ASSERT(pFilter->State == FilterRunning);

    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
    pFilter->State = FilterPausing;
    FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);

    Status = NDIS_STATUS_SUCCESS;

    pFilter->State = FilterPaused;

    DEBUGP(DL_TRACE, "<===FilterPause:  Status %x\n", Status);
    return Status;
}

_Use_decl_annotations_
NDIS_STATUS
FilterRestart(
    NDIS_HANDLE                     FilterModuleContext,
    PNDIS_FILTER_RESTART_PARAMETERS RestartParameters
    )
{
    NDIS_STATUS     Status;
    PMS_FILTER      pFilter = (PMS_FILTER)FilterModuleContext;
    NDIS_HANDLE     ConfigurationHandle = NULL;


    PNDIS_RESTART_GENERAL_ATTRIBUTES NdisGeneralAttributes;
    PNDIS_RESTART_ATTRIBUTES         NdisRestartAttributes;
    NDIS_CONFIGURATION_OBJECT        ConfigObject;

    DEBUGP(DL_TRACE, "===>FilterRestart:   FilterModuleContext %p\n", FilterModuleContext);

    FILTER_ASSERT(pFilter->State == FilterPaused);

    ConfigObject.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
    ConfigObject.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
    ConfigObject.Header.Size = sizeof(NDIS_CONFIGURATION_OBJECT);
    ConfigObject.NdisHandle = FilterDriverHandle;
    ConfigObject.Flags = 0;

    Status = NdisOpenConfigurationEx(&ConfigObject, &ConfigurationHandle);
    if (Status != NDIS_STATUS_SUCCESS)
    {

#if 0
        PWCHAR              ErrorString = L"KillShark";

        DEBUGP(DL_WARN, "FilterRestart: Cannot open configuration.\n");
        NdisWriteEventLogEntry(FilterDriverObject,
                                EVENT_NDIS_DRIVER_FAILURE,
                                0,
                                1,
                                &ErrorString,
                                sizeof(Status),
                                &Status);
#endif

    }

    if (Status == NDIS_STATUS_SUCCESS)
    {
        NdisCloseConfiguration(ConfigurationHandle);
    }

    NdisRestartAttributes = RestartParameters->RestartAttributes;

    if (NdisRestartAttributes != NULL)
    {
        PNDIS_RESTART_ATTRIBUTES   NextAttributes;

        ASSERT(NdisRestartAttributes->Oid == OID_GEN_MINIPORT_RESTART_ATTRIBUTES);

        NdisGeneralAttributes = (PNDIS_RESTART_GENERAL_ATTRIBUTES)NdisRestartAttributes->Data;
        NdisGeneralAttributes->LookaheadSize = 128;

        // Check each attribute to see whether the filter needs to modify it.
        NextAttributes = NdisRestartAttributes->Next;

        while (NextAttributes != NULL)
        {
            NextAttributes = NextAttributes->Next;
        }
    }

    // If everything is OK, set the filter in running state.
    pFilter->State = FilterRunning; // when successful


    Status = NDIS_STATUS_SUCCESS;

    if (Status != NDIS_STATUS_SUCCESS)
    {
        pFilter->State = FilterPaused;
    }


    DEBUGP(DL_TRACE, "<===FilterRestart:  FilterModuleContext %p, Status %x\n", FilterModuleContext, Status);
    return Status;
}


_Use_decl_annotations_
VOID
FilterDetach(
    NDIS_HANDLE     FilterModuleContext
    )
{
    PMS_FILTER                  pFilter = (PMS_FILTER)FilterModuleContext;
    BOOLEAN                      bFalse = FALSE;


    DEBUGP(DL_TRACE, "===>FilterDetach:    FilterInstance %p\n", FilterModuleContext);


    // Filter must be in paused state
    FILTER_ASSERT(pFilter->State == FilterPaused);

    // Free filter instance name if allocated.
    if (pFilter->FilterName.Buffer != NULL)
    {
        FILTER_FREE_MEM(pFilter->FilterName.Buffer);
    }


    FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
    RemoveEntryList(&pFilter->FilterModuleLink);
    FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

    // Free the memory allocated
    FILTER_FREE_MEM(pFilter);

    DEBUGP(DL_TRACE, "<===FilterDetach Successfully\n");
    return;
}

_Use_decl_annotations_
VOID
FilterUnload(
    PDRIVER_OBJECT      DriverObject
    )
{
#if DBG
    BOOLEAN               bFalse = FALSE;
#endif

    UNREFERENCED_PARAMETER(DriverObject);

    DEBUGP(DL_TRACE, "===>FilterUnload\n");

    // Should free the filter context list
    FilterDeregisterDevice();
    NdisFDeregisterFilterDriver(FilterDriverHandle);

#if DBG
    FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
    ASSERT(IsListEmpty(&FilterModuleList));

    FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

#endif

    FILTER_FREE_LOCK(&FilterListLock);

    DEBUGP(DL_TRACE, "<===FilterUnload\n");

    return;

}

_Use_decl_annotations_
VOID
FilterReceiveNetBufferLists(
    NDIS_HANDLE         FilterModuleContext,
    PNET_BUFFER_LIST    NetBufferLists,
    NDIS_PORT_NUMBER    PortNumber,
    ULONG               NumberOfNetBufferLists,
    ULONG               ReceiveFlags
)
{
    PMS_FILTER pFilter = (PMS_FILTER)FilterModuleContext;
    PNET_BUFFER_LIST CurrNetBufferList = NetBufferLists;
    PNET_BUFFER CurrNetBuffer;
    // ULONG DataLength;
    ULONG MappedLength;
    ULONG RemainingData;
    PUCHAR DataBuffer;
    ULONG Offset = 0;
    PETHERNET_FRAME EtherFrame;
    ULONG DstAddress, SrcAddress;
    UINT8 FirstIpOctet, SecndIpOctet, ThirdIpOctet, FourthIpOctet;

    UINT32 targetIp = (172U << 24) | (16U << 16) | (0U << 8) | 138U; // "172.16.0.138"

    //KdPrint(("===> Enter FilterReceiveNetBufferLists\n"));

    for (; CurrNetBufferList; CurrNetBufferList = NET_BUFFER_LIST_NEXT_NBL(CurrNetBufferList))
    {
        CurrNetBuffer = NET_BUFFER_LIST_FIRST_NB(CurrNetBufferList);
        for (; CurrNetBuffer; CurrNetBuffer = NET_BUFFER_NEXT_NB(CurrNetBuffer))
        {
            EtherFrame = NdisGetDataBuffer(
                CurrNetBuffer,
                sizeof(ETHERNET_FRAME),
                NULL, 1, 0
            );

            if (!EtherFrame)
                continue;

            // IPv4 Only
            if (CustomNtohs(EtherFrame->EtherType) != 0x0800)
                continue;

            UINT8 protocol = EtherFrame->InternetProtocol.V4Hdr.Protocol;
            if (!(protocol == 0x01 || protocol == 0x06 || protocol == 0x11)) // Check for ICMP, TCP, UDP
                continue;

            DstAddress = RtlUlongByteSwap(EtherFrame->InternetProtocol.V4Hdr.DestinationIPAddress);
            SrcAddress = RtlUlongByteSwap(EtherFrame->InternetProtocol.V4Hdr.SourceIPAddress);

            if (SrcAddress != targetIp)
                continue;

            // Print Destination and Source IPs
            FirstIpOctet = (UINT8)((SrcAddress >> 24) & 0xFF);
            SecndIpOctet = (UINT8)((SrcAddress >> 16) & 0xFF);
            ThirdIpOctet = (UINT8)((SrcAddress >> 8) & 0xFF);
            FourthIpOctet = (UINT8)(SrcAddress & 0xFF);

            KdPrint(("\nSource IP Address: %u.%u.%u.%u\n",
                FirstIpOctet, SecndIpOctet, ThirdIpOctet, FourthIpOctet));

            FirstIpOctet = (UINT8)((DstAddress >> 24) & 0xFF);
            SecndIpOctet = (UINT8)((DstAddress >> 16) & 0xFF);
            ThirdIpOctet = (UINT8)((DstAddress >> 8) & 0xFF);
            FourthIpOctet = (UINT8)(DstAddress & 0xFF);

            KdPrint(("Destination IP Address: %u.%u.%u.%u\n",
                FirstIpOctet, SecndIpOctet, ThirdIpOctet, FourthIpOctet));

            // Print buffer
            RemainingData = NET_BUFFER_DATA_LENGTH(CurrNetBuffer);
            MappedLength = min(RemainingData, MmGetMdlByteCount(NET_BUFFER_CURRENT_MDL(CurrNetBuffer)) - Offset);
            DataBuffer = NdisGetDataBuffer(CurrNetBuffer, MappedLength, NULL, 1, Offset);

            if (!DataBuffer)
            {
                KdPrint(("Failed to map NET_BUFFER data buffer at offset %lu\n", Offset));
                break;
            }

            PUCHAR TransportLayerData = DataBuffer + sizeof(ETHERNET_FRAME) + sizeof(IPV4_PACKET);
            if (protocol == 0x01) // ICMP
            {
                KdPrint(("Packet Type: ICMP\n"));
            }
            else if (protocol == 0x06) // TCP
            {
                KdPrint(("Packet Type: TCP\n"));

                PETHERNET_FRAME ethernetFrame = (PETHERNET_FRAME)TransportLayerData;
                PIPV4_PACKET ipHeader = (PIPV4_PACKET)((PUCHAR)ethernetFrame + sizeof(ETHERNET_FRAME));

                PUCHAR tcpHeader = (PUCHAR)ipHeader + sizeof(IPV4_PACKET);

                unsigned short tcpDestPort = (tcpHeader[0x24] << 8) | tcpHeader[0x25];

                //tcpDestPort = RtlUlongByteSwap(tcpDestPort);

                KdPrint(("TCP Destination Port: %u\n", tcpDestPort));
            }
            else if (protocol == 0x11) // UDP
            {
                KdPrint(("Packet Type: UDP\n"));
                PUDP_HEADER udpHeader = (PUDP_HEADER)(TransportLayerData);
                KdPrint(("UDP Destination Port: %u\n", RtlUlongByteSwap(udpHeader->DestinationPort)));
            }

            PrintNetBufferContents(CurrNetBuffer);

            RemainingData -= MappedLength;
            Offset += MappedLength;
        }
    }

    if (pFilter->State == FilterRunning)
    {
        NdisFIndicateReceiveNetBufferLists(
            pFilter->FilterHandle,
            NetBufferLists,
            PortNumber,
            NumberOfNetBufferLists,
            ReceiveFlags);
    }
    else
    {
        ULONG ReturnFlags = 0;
        if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
        {
            NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
        }
        NdisFReturnNetBufferLists(pFilter->FilterHandle, NetBufferLists, ReturnFlags);
    }

    //KdPrint(("<=== Exit FilterReceiveNetBufferLists\n"));
}
