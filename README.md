
# Packet Sniffer

Monitors network activity and logs all packets that have been sent/recieved by the client's host.




## Settings

In **Main.kt**, the *PcapHandler* is created with the following defualt parameters

```kotlin
const val TIMEOUT = 10
const val SNAPSHOT_BYTE_LENGTH = 65536
const val PACKET_COUNT = 100
```



## Logs

Everytime a IPv4 or 1Pv6 packet is recieved/sent, the PacketListener will log both the encoded and decoded bytes of the payload and header, replacing all not printable characters with "."

When a packet is sniffed, the logger will only print if the src address has not had it's DNS entry cached. When it is, the following will be logged

```
**** [main] INFO  Packet Stats  - Handled Packet from some.example.source
```
Every minute, a snapshot of all packets will be logged in the following format
```
...
From [some_source] -> ([number of packets sniffed from this source],
                        (
                            [header bytes enocded], 
                            [header bytes decoded]
                        ),
                        (
                            [payload bytes enocded], 
                            [payload bytes decoded]
                        )
                    )
...
```
