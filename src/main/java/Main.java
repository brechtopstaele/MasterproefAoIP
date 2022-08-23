
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.UdpPacket;
import webphone.*;

import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.pcap4j.core.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Main {

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

    static webphone createWebphone(String serverAddress, String username, String password){
        webphone wobj = new webphone();

        //Enter connection details
        wobj.API_SetParameter("serveraddress", serverAddress);
        wobj.API_SetParameter("username", username);
        wobj.API_SetParameter("password", password);

        //Set option for no encryption
        wobj.API_SetParameter("encryption", 0);
        //Set option for no encryption on RTP stream
        wobj.API_SetParameter("mediaencryption", 0);
        //Set transport protocol to UDP
        wobj.API_SetParameter("transport", 0);
        //Set option for RTP stats
        wobj.API_SetParameter("rtpstat", 1);
        //Set option to use RTCP
        wobj.API_SetParameter("rtcp", true);
        //Set option to use Opus codec
        wobj.API_SetParameter("codec", "opus,opuswb,opusuwb,opusswb");

        //Set number of frames per packet
        int framesPerPacket = 0;
        wobj.API_SetParameter("codecframecount", framesPerPacket);

        wobj.API_SetParameter("loglevel", 1);

        wobj.API_Start();
        return wobj;
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        //Create webphone
        webphone wobj = createWebphone("192.168.174.1", "alice", "alice");

        // Choose networkinterface
        PcapNetworkInterface device = getNetworkDevice();
        System.out.println("You chose: " + device);
        if (device == null) {
            System.out.println("No device chosen.");
            System.exit(1);
        }

        System.out.println(device.isLoopBack());

        // Open the device and get a handle
        int snapshotLength = 65536; // captured packet max length in bytes
        int readTimeout = 50; // in milliseconds
        final PcapHandle handle;
        handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);

        List<Integer> fractionsLost = new ArrayList<Integer>();
        List<Integer> cumulativeLost = new ArrayList<Integer>();
        List<Integer> jitter = new ArrayList<Integer>();
        List<Integer> timestamp = new ArrayList<Integer>();

        //Filter for UDP packets
        String filter = "udp";
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        // Create a listener that defines what to do with the received packets
        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                IpPacket IPPacket = (IpPacket) packet.getPayload();
                UdpPacket udpPacket = (UdpPacket) IPPacket.getPayload();
                byte[] raw = udpPacket.getPayload().getRawData();



                if(udpPacket.getHeader().getDstPort().valueAsInt() % 2 == 1 &&  raw.length >= 51){



                    String hex = bytesToHex(raw);
                    //System.out.println(hex); //RTP(C)

                    ByteBuffer buf = ByteBuffer.wrap(raw);
//                    ByteBuffer versionBuf = buf.slice(0,2);
//                    ByteBuffer paddingBuf = buf.slice(2,1);
//                    ByteBuffer reportCountBuf = buf.slice(3,5);

                    ByteBuffer typeBuf = buf.slice(1,1);
                    if(buf.getInt(1) == 200) {
                        System.out.println(packet);
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

                        int fractionLost = fractionLostBuf.getInt();
                        int cumulLost = cumulLostBuf.getInt();
                        int jitter = jitterBuf.getInt();

                        System.out.println(fractionLost);
                        System.out.println(cumulLost);
                        System.out.println(jitter);


                    }
                }

                // Override the default gotPacket() function and process packet
//                System.out.println(packet.getHeader()); //Ethernet
//                System.out.println(packet.getPayload().getHeader()); //IP
//                System.out.println(packet.getPayload().getPayload().getHeader()); //UDP





//                packet.getPayload().getPayload().getPayload().
                //RTCP:
                // 100x xxxx (zoveelste rapport) 1100 1001
                // 0000 0000 0000 0111 (lengte)
                // xxxx xxxx xxxx xxxx
                // xxxx xxxx xxxx xxxx (SSRC)

                // xxxx xxxx xxxx xxxx
                // xxxx xxxx xxxx xxxx (source identifier)
                // xxxx xxxx (fraction lost) xxxx xxxx
                // xxxx xxxx xxxx xxxx (cumulative number lost)
                // xxxx xxxx xxxx xxxx
                // xxxx xxxx xxxx xxxx (highest seq num)
                // xxxx xxxx xxxx xxxx
                // xxxx xxxx xxxx xxxx (interarrival jitter)
                // xxxx xxxx xxxx xxxx
                // xxxx xxxx xxxx xxxx (last SR timestamp)
                // xxxx xxxx xxxx xxxx
                // xxxx xxxx xxxx xxxx (delay since last SR timestamp)


                //int fractionLost = ;
                //int cumulativeLost = ;
                //int jitter = ;
                //int timestamp = ;

//                System.out.println(handle.getTimestamp());
//                System.out.println(packet);
//                System.out.println(raw.length);
            }
        };

        //wobj.API_Call(-1, "bob");

        // Tell the handle to loop using the listener we created
        try {
            int maxPackets = 2000;
            handle.loop(maxPackets, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }


        //wobj.API_Exit();

        // Cleanup when complete
        handle.close();

//        wobj.API_PlaySound(1, "mysound.wav", 1, false, false, true, -1, "", false);
//        wobj.API_RTPStat(-1);
//
//
//        wobj.API_Call(-1, "bob");

    }

}
