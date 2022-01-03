package org.openpacketsniffer
import org.openpacketsniffer.packethandlers.IpPacketHandler
import org.pcap4j.core.PacketListener
import org.pcap4j.packet.AbstractPacket
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.IpV6Packet
import org.pcap4j.packet.Packet

fun <T : Packet> isOfPacket(packet : Packet, packetType : Class<T>): Boolean
{
    return packet.get(packetType) != null
}

var PacketListener =  PacketListener {packet ->

    packet.get(IpV4Packet::class.java).let{
        if(isOfPacket(packet, IpV4Packet::class.java)) IpPacketHandler.handle(it)
    }

    packet.get(IpV6Packet::class.java).let{
        if(isOfPacket(packet, IpV6Packet::class.java)) IpPacketHandler.handle(it)
    }

}