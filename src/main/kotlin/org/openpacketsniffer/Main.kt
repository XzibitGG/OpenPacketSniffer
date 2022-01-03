package org.openpacketsniffer

import org.apache.log4j.BasicConfigurator
import org.pcap4j.core.PcapHandle
import org.pcap4j.core.PcapNetworkInterface
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode
import org.pcap4j.core.Pcaps
import org.openpacketsniffer.SnifferStats
import java.net.InetAddress


val ADDRESS: InetAddress = InetAddress.getLocalHost()
val MODE = PromiscuousMode.PROMISCUOUS

const val TIMEOUT = 10
const val SNAPSHOT_BYTE_LENGTH = 65536

val Network_Interface: PcapNetworkInterface = Pcaps.getDevByAddress(ADDRESS)

fun main() {
    BasicConfigurator.configure()

    val handle: PcapHandle = Network_Interface.openLive(SNAPSHOT_BYTE_LENGTH, MODE, TIMEOUT)

    try {
        handle.loop(50, PacketListener)
    } catch (e: InterruptedException) {
        e.printStackTrace()
    }


    SnifferStats.getReport(handle)

}
