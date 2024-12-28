# KillShark

KillShark NDIS driver designed to perform local proxying on the NDIS layer. Originally thought to mess with the Wireshark's Npcap driver.

## Installation

Build the driver on [KillsharkDriver](https://github.com/zeropio/killshark/tree/main/KillsharkDriver) and load it on `Control Panel -> Network and Internet -> Network and Sharing Centre -> Adapter -> Properties -> Install -> Service -> Browse`.
Modify the IPs and ports on [KillSharkClient](https://github.com/zeropio/killshark/blob/main/KillSharkClient/main.c#L25).
```c
buffer.SourceTargetIp = (172U << 24) | (16U << 16) | (0U << 8) | 138U; // "172.16.0.138"
buffer.SourcePort = 8000;
buffer.DestinationTargetIp = (172U << 24) | (16U << 16) | (0U << 8) | 142U; // "172.16.0.142"
buffer.DestinationPort = 11111;
```

Execute KillSharkClient.exe and enjoy!
