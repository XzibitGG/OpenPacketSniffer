package org.openpacketsniffer.packethandlers
import org.openpacketsniffer.SnifferStats.addPacketStat
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.IpV6Packet


class IpPacketHandler(){
    companion object {

        fun handle(packet : IpV4Packet){
            addPacketStat(packet.header.srcAddr.hostName)

        }

        fun handle(packet : IpV6Packet){
            addPacketStat(packet.header.srcAddr.hostName)
        }


    }
}
