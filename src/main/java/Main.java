
import GUI.Graph;
import GUI.StatPlot;
import PacketListeners.RtcpListener;
import PacketListeners.SipListener;
import Support.Caller;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.Plot;
import org.jfree.chart.ui.UIUtils;
import org.jfree.data.time.DynamicTimeSeriesCollection;
import org.jfree.data.xy.IntervalXYDataset;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeriesCollection;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.UdpPacket;

import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.pcap4j.core.*;
import webphone.webphone;

import javax.swing.*;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;

public class Main {
    //A is self, B is target
    static int rtpPortA, rtpPortB, rtcpPortA, rtcpPortB;

    //Local SIP-server
//    final static String serverIP = "192.168.0.228";
    //VRT SIP-server
    final static String serverIP = "95.130.43.116";
    final static String username = "3227416751";
    final static String password = "vpS24UCxzWD8afKw";
    //Local client
//    final static String target = "3227416750";
    //Radio 1 Opus
    final static String target = "9231";

    static String targetIP;

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

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        //Create webphone
        Caller caller = new Caller();
        caller.createWebphone(serverIP, username, password, target);

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

        // Create packetListeners
        SipListener sipListener = new SipListener();
        sipListener.setCaller(caller);
        RtcpListener rtcpListener = new RtcpListener(target);
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

        webphone wobj = caller.getWebphone();
        wobj.API_GetSIPMessage(-1, 1, 3);

        caller.startCall();

//        System.out.println("_Server address: " + wobj.API_GetParameter("serveraddress"));
//        System.out.println("_Rtcp enabled: " + wobj.API_GetParameter("rtcp"));

        //Try to capture SIP packets for stream detection
        int i = 0;
        while(!(caller.getCallStatus() == 2) && i < 300 ) {
            Packet packet = handle.getNextPacket();
            if(packet != null) sipListener.gotPacket(packet);
            i++;
        }

        System.out.println(wobj.API_GetSIPMessage(-1, 1, 3));
        System.out.println(wobj.API_GetSIPMessage(-1, 0, 4));

        rtpPortB = sipListener.getRtpPortB();
        rtcpPortB = sipListener.getRtcpPortB();
        rtpPortA = sipListener.getRtpPortA();
        rtcpPortA = sipListener.getRtcpPortA();

        System.out.println("Eigen adres volgens wobj: " + wobj.API_GetAddress());
        System.out.println("Eigen adres volgens pcap4j: " + rtcpPortA);


        System.out.println("____________________RTPSTAT:");
        wobj.API_RTPStat(-1);
        System.out.println("________________NEXT:");

        if(caller.getCallStatus() != 2){
            caller.endCall();
            System.out.println("Call not established, check details");
        }else {

            //Capture RTCP packets for jitter and packet loss
            //TODO: B goed?
            //Filter for RTCP packets
            if (rtcpPortB == 0) {
                if (rtpPortB != 0) rtcpPortB = rtpPortB + 1;
                else {
                    findRtcpPort(handle);
                }
            }
            filter = "udp port " + rtcpPortB;
            System.out.println("Listening on: " + rtcpPortB);
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
            int maxPackets = 10;
            try {
                handle.loop(maxPackets, rtcpListener);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        wobj.API_RTPStat(-1);

        //TODO: RTP stream voor verschil in toekomen? -> jitter beetje
        //TODO: mssn ideale jitter buffer berekenen

        //TODO: latency

        //TODO: bandbreedte
        //TODO: mssn ideale bandbreedte berekenen

        // Cleanup when complete
        handle.close();
        caller.endCall();

        //TODO: grafieken over alles

        //create an instance of JFrame class
        JFrame frame = new JFrame();
        // set size, layout and location for frame.
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.add(new Graph(rtcpListener.jitterList));
        frame.setSize(400, 400);
        frame.setLocation(200, 200);
        frame.setVisible(true);


        //TODO OOOOOOOOO

        StatPlot demo = new StatPlot("JFreeChart: BarChartDemo1.java", rtcpListener.jitterList);
        demo.pack();
        UIUtils.centerFrameOnScreen(demo);
        demo.setVisible(true);
    }

    static void findRtcpPort(PcapHandle handle){
        int seqNum = 0;
        while (rtpPortB == 0) {
            try {
                Packet packet = handle.getNextPacketEx();
                IpPacket IPPacket = (IpPacket) packet.getPayload();
                UdpPacket udpPacket = (UdpPacket) IPPacket.getPayload();
                byte[] raw = packet.getPayload().getPayload().getPayload().getRawData();
                ByteBuffer buf = ByteBuffer.wrap(raw);

                String typeBinary = Integer.toBinaryString(buf.slice(0, 1).get());
                if (typeBinary.startsWith("10")) {
                    seqNum = buf.slice(2, 4).getInt();
                    ByteBuffer next = ByteBuffer.wrap(handle.getNextPacketEx().getPayload().getPayload().getPayload().getRawData());
                    if (next.slice(2, 4).getInt() == seqNum + 1) {
                        rtpPortB = udpPacket.getHeader().getDstPort().valueAsInt();
                        rtcpPortB = rtpPortB + 1;
                    }
                }

            } catch (EOFException | TimeoutException | PcapNativeException | NotOpenException e) {
                e.printStackTrace();
            }
        }
    }

}
