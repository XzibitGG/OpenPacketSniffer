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

data class DNSPair<out A, out B>(
    val ipAddress: A,
    val domainName: B
) : Serializable{
    override fun toString(): String {
        if(ipAddress == domainName) return "$ipAddress"

        return "$ipAddress, $domainName"
    }

    override fun equals(other: Any?): Boolean {
        return other.hashCode() == hashCode()
    }

    override fun hashCode(): Int {
        var result = ipAddress?.hashCode() ?: 0
        result = 31 * result + (domainName?.hashCode() ?: 0)
        return result
    }
}
