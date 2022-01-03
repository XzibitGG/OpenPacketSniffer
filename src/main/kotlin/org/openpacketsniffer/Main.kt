package org.openpacketsniffer

import org.apache.log4j.BasicConfigurator
import org.pcap4j.core.PacketListener
import org.pcap4j.core.PcapHandle
import org.pcap4j.core.PcapNetworkInterface
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.IpV4Packet
import java.net.InetAddress


val ADDRESS: InetAddress = InetAddress.getLocalHost()
val MODE = PromiscuousMode.PROMISCUOUS

const val TIMEOUT = 10
const val SNAPSHOT_BYTE_LENGTH = 65536

val Network_Interface: PcapNetworkInterface = Pcaps.getDevByAddress(ADDRESS)

fun configureLogger(){
    BasicConfigurator.configure()
}

fun main() {
    configureLogger()

    val handle: PcapHandle = Network_Interface.openLive(SNAPSHOT_BYTE_LENGTH, MODE, TIMEOUT)

    val listener = PacketListener { packet ->
        if(packet.get(IpV4Packet::class.java) != null){

            val sourceAddress = packet.get(IpV4Packet::class.java).header.dstAddr

            if(sourceAddress != InetAddress.getLocalHost()){
                println(packet.get(IpV4Packet::class.java).header.dstAddr)
            }
        }
    }

    try {
        handle.loop(50, listener)
    } catch (e: InterruptedException) {
        e.printStackTrace()
    }

    val ps = handle.stats
    println("ps_recv: " + ps.numPacketsReceived)
    println("ps_drop: " + ps.numPacketsDropped)
    println("ps_ifdrop: " + ps.numPacketsDroppedByIf)

    handle.close()

}