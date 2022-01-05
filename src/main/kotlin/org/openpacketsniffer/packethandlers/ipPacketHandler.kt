package org.openpacketsniffer.packethandlers
import org.openpacketsniffer.SnifferStats.addPacketStat
import org.openpacketsniffer.util.PacketInfoPair
import org.openpacketsniffer.util.PacketTypePair
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.IpV6Packet

class IpPacketHandler() {
    companion object {

        private fun getInfo(bytes: ByteArray): PacketInfoPair<String, String> {
            return PacketInfoPair(bytes.joinToString(" "), String(bytes).replace("\\p{C}".toRegex(), "."))
        }

        fun handle(packet: IpV4Packet) {
            addPacketStat(packet.header.srcAddr, PacketTypePair(getInfo(packet.header.rawData), getInfo(packet.payload.rawData)))
        }

        fun handle(packet: IpV6Packet) {
            addPacketStat(packet.header.srcAddr, PacketTypePair(getInfo(packet.header.rawData), getInfo(packet.payload.rawData)))
        }
    }
}
