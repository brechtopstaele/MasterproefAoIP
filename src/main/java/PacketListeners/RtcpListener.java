package PacketListeners;

import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;
import org.apache.commons.net.ntp.TimeStamp;
import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class RtcpListener implements PacketListener {
    String targetAddress = null;
    private final String os = System.getProperty("os.name").toLowerCase();

    int reportCount;
    public List<Integer> fractionsLostList;
    public List<Integer> cumulativeLostList;
    public List<Integer> jitterList;

    public RtcpListener(String targetAddress) {
        this.targetAddress = targetAddress;
        reportCount = 0;
        fractionsLostList = new ArrayList<Integer>();
        cumulativeLostList = new ArrayList<Integer>();
        jitterList = new ArrayList<Integer>();
    }



    public String traceRoute(){
        String route = "";
        try {
            Process traceRt;
            if(os.contains("win")) traceRt = Runtime.getRuntime().exec("tracert " + targetAddress);
            else traceRt = Runtime.getRuntime().exec("traceroute " + targetAddress);

            // read the output from the command
            route = new BufferedReader(new InputStreamReader(traceRt.getInputStream())).lines().collect(Collectors.joining("\n"));

            // read any errors from the attempted command
            String errors = new BufferedReader(new InputStreamReader(traceRt.getErrorStream())).lines().collect(Collectors.joining("\n"));
            if(!Objects.equals(errors, "")) System.out.println(errors);
        }
        catch (IOException e) {
            System.out.println("error while performing trace route command" + e);
        }
        return route;
    }

    private long getNTPOffset(){
        long offsetValue = 0;
        NTPUDPClient client = new NTPUDPClient();
        try {
            client.open();
            InetAddress hostAddr = InetAddress.getByName("pool.ntp.org");
            TimeInfo info = client.getTime(hostAddr);
            info.computeDetails(); // compute offset/delay if not already done
            offsetValue = info.getOffset();
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return offsetValue;
    }

    @Override
    public void gotPacket(Packet packet) {
        IpPacket IPPacket = (IpPacket) packet.getPayload();
        UdpPacket udpPacket = (UdpPacket) IPPacket.getPayload();
        byte[] raw = udpPacket.getPayload().getRawData();
        ByteBuffer buf = ByteBuffer.wrap(raw);

        if (raw.length >= 51) {
            ByteBuffer detailBuf = buf.slice(0,1);
            String typeBinary = String.format("%8s", Integer.toBinaryString(detailBuf.get() & 0xFF)).replace(' ', '0');
            if (typeBinary.startsWith("10")){
                if(String.format("%8s", Integer.toBinaryString(buf.get(1) & 0xFF)).replace(' ', '0').equals("11001000")) {
//                    ByteBuffer lengthBuf = buf.slice(2, 2);
//                    ByteBuffer SSRCBuf = buf.slice(4, 4);
                    ByteBuffer NTPTimestampBuf = buf.slice(8, 8);
                    ByteBuffer RTPTimestampBuf = buf.slice(16, 4);

//                    ByteBuffer senderPacketCountBuf = buf.slice(20, 4);
//                    ByteBuffer senderOctetCountBuf = buf.slice(24, 4);

//                    ByteBuffer SourceIdentifierBuf = buf.slice(28, 4);
                    ByteBuffer fractionLostBuf = buf.slice(32, 1);
                    // Starts one byte to early for easier parsing
                    ByteBuffer cumulLostBuf = buf.slice(32, 4);
                    cumulLostBuf.put(0, (byte) 0);

//                    ByteBuffer highestSeqBuf = buf.slice(36, 4);
                    ByteBuffer jitterBuf = buf.slice(40, 4);
//                    ByteBuffer lastTimestampBuf = buf.slice(44, 4);
//                    ByteBuffer lastTimestampDelayBuf = buf.slice(48, 4);

                    long NTPTimestamp = NTPTimestampBuf.getLong();
                    long timestampJava = TimeStamp.getTime(NTPTimestamp);
                    long offsetValue = getNTPOffset();

                    int rtpTimestamp = RTPTimestampBuf.getInt();

                    long latency = System.currentTimeMillis() + offsetValue - timestampJava;
                    System.out.println("latency: " + latency + "=" + " System.currentTimeMillis(): " + System.currentTimeMillis() + " + offsetValue: " + offsetValue + " - timeStamp: " + timestampJava);


                    int fractionLost = fractionLostBuf.get();
                    fractionsLostList.add(fractionLost);
                    int cumulLost = cumulLostBuf.getInt();
                    cumulativeLostList.add(cumulLost);
                    int jitter = jitterBuf.getInt();
                    jitterList.add(jitter);

                    System.out.println("latency: " + latency);

                    System.out.println("fraction lost: " +fractionLost);
                    System.out.println("cumulative lost: " + cumulLost);
                    System.out.println("jitter: " + jitter);

                    if(jitter > 300 || fractionLost > 5){
                        System.out.println(traceRoute());
                    }

                }
                if (Integer.parseInt(typeBinary.substring(3,5)) == reportCount++) {
                    System.out.println(reportCount);
                } else {
                    reportCount = Integer.parseInt(typeBinary.substring(3,5));
                }
            }
        }
    }
}
