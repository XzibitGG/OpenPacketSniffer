package org.openpacketsniffer

import org.pcap4j.core.PcapHandle

object SnifferStats {

    private var packetStats : HashMap<String, Int> = HashMap<String, Int>()

    fun addPacketStat(K : String){
        packetStats[K] = (packetStats[K] ?: 0) + 1
    }

    fun getReport(handle : PcapHandle){
        packetStats.forEach { (key, value) ->
            println("From $key -> $value received")
        }


        println("Packets Received: " + handle.stats.numPacketsReceived)
        println("Packets Dropped: " + handle.stats.numPacketsDropped)
        println("Packets If Dropped: " + handle.stats.numPacketsDroppedByIf)
    }



}