#pragma pack(push, 1)
typedef struct _IPV4_PACKET {
    struct
    {
        // Order reversed due to MSVC
        UCHAR HeaderLength : 4;
        UCHAR Version : 4;
    }s1;
    UCHAR TypeOfService;
    USHORT TotalLength;
    USHORT Identification;
    struct
    {
        USHORT Flags : 3;
        USHORT FragmentOffset : 13;
    }s2;
    UCHAR TimeToLive;
    UCHAR Protocol;
    USHORT HeaderChecksum;
    ULONG SourceIPAddress;
    ULONG DestinationIPAddress;
} IPV4_PACKET, * PIPV4_PACKET;

typedef struct _ETHERNET_FRAME {
    UCHAR DestinationMac[6];
    UCHAR SourceMac[6];
    USHORT EtherType;
    union
    {
        IPV4_PACKET V4Hdr;
    } InternetProtocol;
} ETHERNET_FRAME, * PETHERNET_FRAME;
#pragma pack(pop)