package org.openpacketsniffer.packethandlers

import org.openpacketsniffer.PacketListener
import org.openpacketsniffer.SnifferStats.addPacketStat
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.IpV6Packet
import org.pcap4j.packet.Packet
import java.net.InetAddress

class IpPacketHandler(){
    companion object {

        fun handle(packet : IpV4Packet){
            (packet.header.dstAddr).let {
                if (it != InetAddress.getLocalHost()) addPacketStat(it.hostAddress)
            }
        }

        fun handle(packet : IpV6Packet){
            (packet.header.dstAddr).let {
                if (it != InetAddress.getLocalHost()) addPacketStat(it.hostAddress)
            }
        }


    }
}
