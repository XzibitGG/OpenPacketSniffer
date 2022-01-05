package org.openpacketsniffer

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import kotlinx.coroutines.runBlocking
import org.openpacketsniffer.util.DNSPair
import org.openpacketsniffer.util.PacketInfoPair
import org.openpacketsniffer.util.PacketTypePair
import org.openpacketsniffer.util.SegmentPair
import java.net.InetAddress

val gson: Gson = GsonBuilder().setPrettyPrinting().create()

object SnifferStats {

    private var DnsEntries: HashMap<String, String> = HashMap()
    private var SniffedSources : ArrayList<String> = ArrayList()

    private var packetStats: HashMap<DNSPair<String, String>,
        ArrayList<
            SegmentPair<Int,
                PacketTypePair<
                    PacketInfoPair<String, String>,
                    PacketInfoPair<String, String>
                    >
                >
            >
        > = HashMap()
    private var Logger = org.apache.log4j.Logger.getLogger("Packet Stats")

    fun addPacketStat(
        K: InetAddress,
        V: PacketTypePair<
            PacketInfoPair<String, String>,
            PacketInfoPair<String, String>
            >
    ) {

        val hostAddress = K.hostAddress

        val pair = DNSPair(hostAddress, DnsEntries[hostAddress] ?: "")

        if (hostAddress !in SniffedSources) {

            Logger.info("Handled Packet from $K ${if(DnsEntries[hostAddress] != null) "(" + DnsEntries[hostAddress]  + ")" else ""}" )
            packetStats[pair] = ArrayList()

            SniffedSources.add(hostAddress)
        }
        packetStats[pair]?.add(
            SegmentPair(
                (packetStats[pair]?.size ?: 0),
                V
            )
        )

        runBlocking {
            val domainName = K.hostName
            DnsEntries[hostAddress] = domainName
            SniffedSources.add(hostAddress)

            packetStats.remove(DNSPair(hostAddress, ""))?.let {
                packetStats.put(DNSPair(hostAddress, domainName), it)
            }
        }
    }

    fun getReport() {
        Logger.info(gson.toJson(packetStats).toString())

        Logger.info("Total packets: " + packetStats.map { (_, value) -> value.size }.sum())
    }
}
