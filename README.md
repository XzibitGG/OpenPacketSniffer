
# Packet Sniffer

Monitors network activity and logs all packets that have been sent/received by the client's host.




## Settings

In **Main.kt**, the *PcapHandler* is created with the following default parameters

```kotlin
const val TIMEOUT = 10
const val SNAPSHOT_BYTE_LENGTH = 65536
const val PACKET_COUNT = 100
```



## Logs

Everytime a IPv4 or 1Pv6 packet is received/sent, the PacketListener will log both the encoded and decoded bytes of the payload and header, replacing all not printable characters with "."

When a packet is sniffed, the logger will only print if the src address' DNS entry wasn't cached. When it is, the following will be logged

```yaml
XXXX [main] INFO  Packet Stats  - Handled Packet from some.example.source
```
Every minute, a snapshot of all packets will be logged in the following format
```yaml
...
From [some_source] -> (<index of packet>, [
                            ...
                            (
                                <header bytes enocded>, 
                                <header bytes decoded>
                            ),
                            (
                                <payload bytes enocded>, 
                                <payload bytes decoded>
                            )
                            ...
                        ]
                    )
...
```
