
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.UdpPacket;

import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.pcap4j.core.*;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;

public class Main {
    static int rtpPortA, rtpPortB, rtcpPortA, rtcpPortB;
    final static String serverIP = /*"192.168.0.228"*/"95.130.43.116";
    final static String username = "3227416751";
    final static String password = "vpS24UCxzWD8afKw";
    final static String target = "3227416750";

    static int reportCount = 0;

    //RTP variables
    static int seqNum, prevTimestamp, rtpTimestamp;
    static List<Integer> rtpTimeDifList = new ArrayList<>();


    static PcapNetworkInterface getNetworkDevice() {
        PcapNetworkInterface device = null;
        try {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return device;
    }

    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
    public static String bytesToHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }



    private static List<ByteBuffer> splitSIPMessage(ByteBuffer buf){
        List<ByteBuffer> bufferList = new ArrayList<>();
        byte[] array = buf.array();
        int prevCut = 0;
        for(int i = 0; i < array.length; i++){
            if(array[i] == (byte) 13 && array[i+1] == (byte) 10){
                bufferList.add(buf.slice(prevCut,i-prevCut));
                i++;
                prevCut = i+1;
            }
        }
        return bufferList;
    }



    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        //Create webphone
        Caller caller = new Caller();
        caller.createWebphone(serverIP, username, password);

        // Choose networkinterface
        PcapNetworkInterface device = getNetworkDevice();
        System.out.println("You chose: " + device);
        if (device == null) {
            System.out.println("No device chosen.");
            System.exit(1);
        }

        // Open the device and get a handle
        int snapshotLength = 65536; // captured packet max length in bytes
        int readTimeout = 50; // in milliseconds
        final PcapHandle handle;
        handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
//        handle.setDirection(PcapHandle.PcapDirection.INOUT);

        List<Integer> fractionsLostList = new ArrayList<Integer>();
        List<Integer> cumulativeLostList = new ArrayList<Integer>();
        List<Integer> jitterList = new ArrayList<Integer>();
        List<Integer> timestamp = new ArrayList<Integer>();



        // Create a listener that defines what to do with the received packets
        PacketListener sipListener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {

                IpPacket IPPacket = (IpPacket) packet.getPayload();
                UdpPacket udpPacket = (UdpPacket) IPPacket.getPayload();
                byte[] raw = udpPacket.getPayload().getRawData();
                ByteBuffer buf = ByteBuffer.wrap(raw);
                boolean invite = false;

                if (raw.length >= 200) {
                    ByteBuffer requestLineBuf = buf.slice(0, 14);
                    Charset charset = StandardCharsets.UTF_8;
                    String sip = charset.decode(requestLineBuf).toString();
                    //prints out entire sip message
//                    String sip = new String(statusBuf.array());
                    System.out.println();
                    System.out.println("----------new packet----------");
                    if (sip.contains("INVITE sip:") || sip.equals("SIP/2.0 200 OK")) {
                        if (sip.contains("INVITE sip:")) invite = true;
                        String[] mediaDetails = null;
                        String[] rtcpDetails = null;
                        boolean foundMedia = false;
                        boolean foundRtcp = false;
                        ByteBuffer b;
                        int i = 0;
                        List<ByteBuffer> sipBufferList = splitSIPMessage(buf);
                        while ((!foundMedia || !foundRtcp) && i < sipBufferList.size()) {
                            b = sipBufferList.get(i);
                            if (b.capacity() >= 2 && charset.decode(b.slice(0, 2)).toString().equals("m=")) {
                                mediaDetails = charset.decode(b).toString().split(" ");
                                foundMedia = true;
                            } else if (b.capacity() >= 6 && charset.decode(b.slice(0, 6)).toString().equals("a=rtcp")) {
                                rtcpDetails = charset.decode(b).toString().split(" ");
                                foundRtcp = true;
                            }
                            i++;
                        }

                        if(mediaDetails != null) {
                            if (invite) rtpPortA = Integer.parseInt(mediaDetails[1]);
                            else rtpPortB = Integer.parseInt(mediaDetails[1]);
                            //Testoutput
                            System.out.println("___RTP Port B: " + rtpPortB);
                            System.out.println("___RTP Port A: " + rtpPortA);
                            System.out.println("___Media Protocol: " + mediaDetails[2]);
                            System.out.println("___Media Format: " + mediaDetails[3]);
                        }else{
                            System.out.println("++++++++++++++No mediadetails found");
                            System.out.println(charset.decode(buf));
                            System.out.println(sipBufferList.size());
                            for(ByteBuffer bb: sipBufferList){
                                System.out.println(charset.decode(bb));
                            }
                            System.out.println((byte) 15);
                            System.out.println(Arrays.toString(raw));
                        }

                        if(rtcpDetails != null) {
                            System.out.println(charset.decode(buf));
                            if (invite) rtcpPortA = Integer.parseInt(rtcpDetails[0].split(":")[1]);
                            else rtcpPortB = Integer.parseInt(rtcpDetails[0].split(":")[1]);
                            //Testoutput
                            System.out.println("___RTCP Port B: " + rtcpPortB);
                        }else{
                            System.out.println("++++++++++++++No rtcpdetails found");
                            System.out.println(charset.decode(buf));
                            System.out.println(sipBufferList.size());
                            for(ByteBuffer bb: sipBufferList){
                                System.out.println(charset.decode(bb));
                            }
                        }
                    }
                }
            }
        };

        PacketListener rtcpListener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                IpPacket IPPacket = (IpPacket) packet.getPayload();
                UdpPacket udpPacket = (UdpPacket) IPPacket.getPayload();
                byte[] raw = udpPacket.getPayload().getRawData();
                ByteBuffer buf = ByteBuffer.wrap(raw);

                if (raw.length >= 51) {
                    ByteBuffer detailBuf = buf.slice(0,1);
                    String typeBinary = Integer.toBinaryString(detailBuf.getInt());
                    if (typeBinary.startsWith("10")){
                        if(buf.getInt(1) == 200) {
                            //TODO: kuisen
                            ByteBuffer lengthBuf = buf.slice(2, 2);
                            ByteBuffer SSRCBuf = buf.slice(4, 4);
                            ByteBuffer NTPTimestampBuf = buf.slice(8, 8);
                            ByteBuffer RTPTimestampBuf = buf.slice(16, 4);

                            ByteBuffer senderPacketCountBuf = buf.slice(20, 4);
                            ByteBuffer senderOctetCountBuf = buf.slice(24, 4);

                            ByteBuffer SourceIdentifierBuf = buf.slice(28, 4);
                            ByteBuffer fractionLostBuf = buf.slice(32, 1);
                            ByteBuffer cumulLostBuf = buf.slice(33, 3);
                            ByteBuffer highestSeqBuf = buf.slice(36, 4);
                            ByteBuffer jitterBuf = buf.slice(40, 4);
                            ByteBuffer lastTimestampBuf = buf.slice(44, 4);
                            ByteBuffer lastTimestampDelayBuf = buf.slice(48, 4);

                            long NTPTimestamp = NTPTimestampBuf.getLong();
                            //TODO: get NTP timestamp
                            long latency = System.nanoTime() - NTPTimestamp;


                            int fractionLost = fractionLostBuf.getInt();
                            fractionsLostList.add(fractionLost);
                            int cumulLost = cumulLostBuf.getInt();
                            cumulativeLostList.add(cumulLost);
                            int jitter = jitterBuf.getInt();
                            jitterList.add(jitter);
                            handle.getTimestamp();

                            System.out.println(NTPTimestamp);
                            System.out.println(latency);

                            System.out.println(fractionLost);
                            System.out.println(cumulLost);
                            System.out.println(jitter);
                        }
                        if (Integer.parseInt(typeBinary.substring(3,5)) == reportCount++) {
                            System.out.println(reportCount);
                        } else {
                            reportCount = Integer.parseInt(typeBinary.substring(3,5));
                        }
                    }
                }
            }
        };


        PacketListener rtpListener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                IpPacket IPPacket = (IpPacket) packet.getPayload();
                UdpPacket udpPacket = (UdpPacket) IPPacket.getPayload();
                byte[] raw = udpPacket.getPayload().getRawData();
                ByteBuffer buf = ByteBuffer.wrap(raw);

                if(udpPacket.getHeader().getSrcPort().valueAsInt() == rtpPortB){
                    if(buf.slice(2,2).getInt() == seqNum){
                        rtpTimestamp = buf.slice(4, 4).getInt();
                        rtpTimeDifList.add(rtpTimestamp - prevTimestamp);
                        prevTimestamp = rtpTimestamp;
                        seqNum++;
                    }
                }

                //TODO: andere richting ook?
                //TODO: wat als rtpPortA niet te pakken?
            }
        };

        //Filter for UDP packets
        String filter = "udp";
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        while(!caller.isRegistered()){

        }

        System.out.println("Press enter to start call");
        Scanner sc = new Scanner(System.in);
        sc.next();

        caller.run(target);

        //Try to capture SIP packets for stream detection
        int maxPackets = 100;
        try {
            handle.loop(maxPackets, sipListener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        //Capture RTCP packets for jitter and packet loss
        //TODO: B goed?
        //Filter for RTCP packets
        if(rtcpPortB == 0){
            if(rtpPortB != 0) rtcpPortB = rtpPortB+1;
            else{
                while (rtpPortB == 0){
                    try{
                        Packet packet = handle.getNextPacketEx();
                        IpPacket IPPacket = (IpPacket) packet.getPayload();
                        UdpPacket udpPacket = (UdpPacket) IPPacket.getPayload();
                        byte[] raw = packet.getPayload().getPayload().getPayload().getRawData();
                        ByteBuffer buf = ByteBuffer.wrap(raw);

                        String typeBinary = Integer.toBinaryString(buf.slice(0,1).get());
                        if (typeBinary.startsWith("10")) {
                            seqNum = buf.slice(2,4).getInt();
                            ByteBuffer next = ByteBuffer.wrap(handle.getNextPacketEx().getPayload().getPayload().getPayload().getRawData());
                            if(next.slice(2,4).getInt() == seqNum + 1){
                                rtpPortB = udpPacket.getHeader().getDstPort().valueAsInt();
                                rtcpPortB = rtpPortB + 1;
                            }
                        }

                    } catch (EOFException | TimeoutException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        filter = "udp port " + rtcpPortB;
        System.out.println("Listening on: " + rtcpPortB);
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        maxPackets = 1000;
        try{
            handle.loop(maxPackets, rtcpListener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        //TODO: RTP stream voor verschil in toekomen? -> jitter beetje
        //TODO: mssn ideale jitter buffer berekenen

        //TODO: latency

        //TODO: bandbreedte
        //TODO: mssn ideale bandbreedte berekenen

        // Cleanup when complete
        handle.close();
        caller.endCall();

        //TODO: grafieken over alles

//        wobj.API_PlaySound(1, "mysound.wav", 1, false, false, true, -1, "", false);
//        wobj.API_RTPStat(-1);
//
//
//        wobj.API_Call(-1, "bob");

    }

}
