package org.openpacketsniffer

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import org.openpacketsniffer.util.PacketInfoPair
import org.openpacketsniffer.util.PacketTypePair
import org.openpacketsniffer.util.SegmentPair

val gson: Gson = GsonBuilder().setPrettyPrinting().create()

object SnifferStats {

    private var packetStats: HashMap<String,
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
        K: String,
        V: PacketTypePair<
                PacketInfoPair<String, String>,
                PacketInfoPair<String, String>
                >
    ) {
        if (K !in packetStats) {
            Logger.info("Handled Packet from $K")
            packetStats[K] = ArrayList()
        }
        packetStats[K]?.add(
            SegmentPair(
                    (packetStats[K]?.size ?: 0),
                        V
                    )
                )
    }

    fun getReport() {
        Logger.info(gson.toJson(packetStats).toString())

        Logger.info("Total packets: " + packetStats.map { (_, value) -> value.size }.sum())
    }
}
