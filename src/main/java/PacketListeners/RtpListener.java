//package PacketListeners;
//
//import org.pcap4j.core.PacketListener;
//import org.pcap4j.packet.IpPacket;
//import org.pcap4j.packet.Packet;
//import org.pcap4j.packet.UdpPacket;
//
//import java.nio.ByteBuffer;
//
//public class RtpListener implements PacketListener {
//    @Override
//    public void gotPacket(Packet packet) {
//        IpPacket IPPacket = (IpPacket) packet.getPayload();
//        UdpPacket udpPacket = (UdpPacket) IPPacket.getPayload();
//        byte[] raw = udpPacket.getPayload().getRawData();
//        ByteBuffer buf = ByteBuffer.wrap(raw);
//
//        if(udpPacket.getHeader().getSrcPort().valueAsInt() == rtpPortB){
//            if(buf.slice(2,2).getInt() == seqNum){
//                rtpTimestamp = buf.slice(4, 4).getInt();
//                rtpTimeDifList.add(rtpTimestamp - prevTimestamp);
//                prevTimestamp = rtpTimestamp;
//                seqNum++;
//            }
//        }
//
//        //TODO: andere richting ook?
//        //TODO: wat als rtpPortA niet te pakken?
//    }
//}
