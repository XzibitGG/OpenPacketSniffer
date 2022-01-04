package org.openpacketsniffer

import org.pcap4j.core.PcapHandle

object SnifferStats {

    private var packetStats: HashMap<String,
                ArrayList<
                    Pair<Int,
                        Pair<
                            Pair<String, String>,
                            Pair<String, String>
                            >
                    >
                >
            > = HashMap()
    private var Logger = org.apache.log4j.Logger.getLogger("Packet Stats")

    fun addPacketStat(
        K: String,
        V: Pair<
            Pair<String, String>,
            Pair<String, String>
            >
    ) {
        if (K !in packetStats) {
            Logger.info("Handled Packet from $K")
            packetStats[K] = ArrayList()
        }
        packetStats[K]?.add(
            Pair(
                    (packetStats[K]?.size ?: 0),
                        V
                    )
                )
    }

    fun getReport(handle: PcapHandle) {
        packetStats.forEach { (key, value) ->
            println("From $key -> $value received")
        }

        println("Packets Received: " + handle.stats.numPacketsReceived)
        println("Packets Dropped: " + handle.stats.numPacketsDropped)
        println("Packets If Dropped: " + handle.stats.numPacketsDroppedByIf)
    }
}
