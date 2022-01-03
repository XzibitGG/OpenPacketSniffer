package org.openpacketsniffer

import org.pcap4j.core.PcapHandle

object SnifferStats {

    private var packetStats : HashMap<String, Int> = HashMap()
    private var Logger = org.apache.log4j.Logger.getLogger("Packet Stats")

    fun addPacketStat(K : String){
        if(K !in packetStats) Logger.info("Handled Packet from $K")
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