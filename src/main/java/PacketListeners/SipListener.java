package PacketListeners;

import Support.Caller;
import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SipListener implements PacketListener {
    boolean foundMediaA = false;
    boolean foundMediaB = false;
    boolean foundRtcpA = false;
    boolean foundRtcpB = false;

    int rtpPortA, rtpPortB, rtcpPortA, rtcpPortB;

    String targetIP;

    Caller caller;

    private static List<ByteBuffer> splitSIPMessage(ByteBuffer buf) {
        List<ByteBuffer> bufferList = new ArrayList<>();
        byte[] array = buf.array();
        int prevCut = 0;
        for (int i = 0; i < array.length; i++) {
            if (array[i] == (byte) 13 && array[i + 1] == (byte) 10) {
                bufferList.add(buf.slice(prevCut, i - prevCut));
                i++;
                prevCut = i + 1;
            }
        }
        return bufferList;
    }

    public int getRtpPortB() {
        return rtpPortB;
    }

    public int getRtcpPortB() {
        return rtcpPortB;
    }

    public int getRtpPortA() {
        return rtpPortA;
    }

    public int getRtcpPortA() {
        return rtcpPortA;
    }

    public void setCaller(Caller caller) {
        this.caller = caller;
    }

    @Override
    public void gotPacket(Packet packet) {

        IpPacket IPPacket = (IpPacket) packet.getPayload();
        UdpPacket udpPacket = (UdpPacket) IPPacket.getPayload();
        byte[] raw = udpPacket.getPayload().getRawData();
        ByteBuffer buf = ByteBuffer.wrap(raw);
        boolean invite = false;

//        if (IPPacket.getHeader().getSrcAddr().toString().equals(caller.getServer()) || IPPacket.getHeader().getDstAddr().toString().equals(caller.getServer())) {
            if (raw.length >= 200) {
                Charset charset = StandardCharsets.UTF_8;
                List<ByteBuffer> sipBufferList = splitSIPMessage(buf);
                //prints out entire sip message
//                    String sip = new String(statusBuf.array());
//            System.out.println();
//            System.out.println("----------new packet----------");
                if (sipBufferList.size() > 0) {
                    String requestLine = charset.decode(sipBufferList.get(0)).toString();
                    if (requestLine.contains("INVITE sip:") || requestLine.equals("SIP/2.0 200 OK")) {
                        //TODO: eventueel check voor juiste sip username
                        if (requestLine.contains("INVITE sip:")) {
                            invite = true;
                        }
                        String[] mediaDetails = null;
                        String[] rtcpDetails = null;

                        ByteBuffer b;
                        int i = 0;

                        while ((!foundMediaA || !foundRtcpA) && i < sipBufferList.size()) {
                            b = sipBufferList.get(i);
                            if (b.capacity() >= 2 && charset.decode(b.slice(0, 2)).toString().equals("m=")) {
                                mediaDetails = charset.decode(b).toString().split(" ");
                                foundMediaA = true;
                            } else if (b.capacity() >= 6 && charset.decode(b.slice(0, 6)).toString().equals("a=rtcp")) {
                                rtcpDetails = charset.decode(b).toString().split(" ");
                                if (rtcpDetails.length > 1) foundRtcpA = true;
                                else rtcpDetails = null;
                            } else if (b.capacity() >= 2 && charset.decode(b.slice(0, 2)).toString().equals("o=")) {
                                targetIP = charset.decode(b).toString().split(" ")[5];
                            }
                            i++;
                        }
                        while ((!foundMediaB || !foundRtcpB) && i < sipBufferList.size()) {
                            b = sipBufferList.get(i);
                            if (b.capacity() >= 2 && charset.decode(b.slice(0, 2)).toString().equals("m=")) {
                                mediaDetails = charset.decode(b).toString().split(" ");
                                foundMediaB = true;
                            } else if (b.capacity() >= 6 && charset.decode(b.slice(0, 6)).toString().equals("a=rtcp")) {
                                rtcpDetails = charset.decode(b).toString().split(" ");
                                if (rtcpDetails.length > 1) foundRtcpB = true;
                                else rtcpDetails = null;
                            }
                            i++;
                        }


                        if (mediaDetails != null) {
                            if (invite) rtpPortA = Integer.parseInt(mediaDetails[1]);
                            else rtpPortB = Integer.parseInt(mediaDetails[1]);
                            //Testoutput
                            System.out.println("___RTP Port B: " + rtpPortB);
                            System.out.println("___RTP Port A: " + rtpPortA);
                            System.out.println("___Media Protocol: " + mediaDetails[2]);
                            System.out.println("___Media Format: " + mediaDetails[3]);
                        } else {
                            System.out.println("++++++++++++++No mediadetails found");
                            System.out.println(charset.decode(buf));
                            System.out.println(sipBufferList.size());
                            for (ByteBuffer bb : sipBufferList) {
                                System.out.println(charset.decode(bb));
                            }
                            System.out.println((byte) 15);
                            System.out.println(Arrays.toString(raw));
                        }

                        if (rtcpDetails != null) {
                            System.out.println(charset.decode(buf));
                            if (invite) rtcpPortA = Integer.parseInt(rtcpDetails[0].split(":")[1]);
                            else rtcpPortB = Integer.parseInt(rtcpDetails[0].split(":")[1]);
                            //Testoutput
                            System.out.println("___RTCP Port B: " + rtcpPortB);
                        } else {
                            if (foundRtcpA) {
                                rtcpPortA = rtpPortA;
                            }
                            if (foundRtcpB) {
                                rtcpPortB = rtpPortB;
                            }
                            System.out.println("++++++++++++++No rtcpdetails found");
                            System.out.println(charset.decode(buf));
//                            System.out.println(sipBufferList.size());
//                            for (ByteBuffer bb : sipBufferList) {
//                                System.out.println(charset.decode(bb));
//                            }
                        }
                    }
                }
            }
        }
//    }
}
