package RTCPPacket;

import org.pcap4j.packet.Packet;

import java.util.Iterator;

public class RtcpPacket implements Packet {
    @Override
    public RtcpHeader getHeader() {
        return null;
    }

    @Override
    public Packet getPayload() {
        return null;
    }

    @Override
    public int length() {
        return 0;
    }

    @Override
    public byte[] getRawData() {
        return new byte[0];
    }

    @Override
    public <T extends Packet> T get(Class<T> aClass) {
        return null;
    }

    @Override
    public Packet getOuterOf(Class<? extends Packet> aClass) {
        return null;
    }

    @Override
    public <T extends Packet> boolean contains(Class<T> aClass) {
        return false;
    }

    @Override
    public Builder getBuilder() {
        return null;
    }

    @Override
    public Iterator<Packet> iterator() {
        return null;
    }
}
