package org.openpacketsniffer.util
import java.io.Serializable

data class PacketInfoPair<out A, out B>(
    val encoded: A,
    val decoded: B
) : Serializable

data class PacketTypePair<out A, out B>(
    val header: A,
    val payload: B
) : Serializable

data class SegmentPair<out A, out B>(
    val index: A,
    val data: B
) : Serializable