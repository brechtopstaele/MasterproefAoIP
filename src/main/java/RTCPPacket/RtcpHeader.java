package RTCPPacket;

import org.pcap4j.packet.Packet;

public class RtcpHeader implements Packet.Header {


    @Override
    public int length() {
        return 0;
    }

    @Override
    public byte[] getRawData() {
        return new byte[0];
    }
}
