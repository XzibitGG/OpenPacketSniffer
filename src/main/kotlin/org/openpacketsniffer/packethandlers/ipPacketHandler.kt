package org.openpacketsniffer.packethandlers
import org.openpacketsniffer.SnifferStats.addPacketStat
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.IpV6Packet

class IpPacketHandler() {
    companion object {

        private fun getInfo(bytes: ByteArray): Pair<String, String> {
            return Pair(bytes.joinToString(" "), String(bytes).replace("\\p{C}".toRegex(), "."))
        }

        fun handle(packet: IpV4Packet) {
            addPacketStat(packet.header.srcAddr.hostName, Pair(getInfo(packet.header.rawData), getInfo(packet.payload.rawData)))
        }

        fun handle(packet: IpV6Packet) {
            addPacketStat(packet.header.srcAddr.hostName, Pair(getInfo(packet.header.rawData), getInfo(packet.payload.rawData)))
        }
    }
}
