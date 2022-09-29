package Support;

import webphone.webphone;

public class Caller extends Thread{
    private webphone wobj;
    private String serverIP;
    private String targetIP;

    public void startCall(){
        wobj.API_Call(-1, targetIP);
    }

    public webphone getWebphone(){
        return wobj;
    }

    public String getTarget(){
        return targetIP;
    }
    public String getServer(){
        return serverIP;
    }

    public void endCall(){
        wobj.API_Stop();
        wobj.API_Exit();
    }

    public boolean isRegistered(){
        return wobj.API_IsRegistered();
    }

    public int getCallStatus(){
        return wobj.API_IsInCall();
    }

    public void createWebphone(String serverAddress, String username, String password, String target){
        this.targetIP = target;
        this.serverIP = serverAddress;

        wobj = new webphone();

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
//        wobj.API_SetParameter("rtpstat", 1);

        //Set option to use RTCP
//        wobj.API_SetParameter("rtcp", true);

        //TODO: andere codecs?
        //Set option to use Opus codec
//        wobj.API_SetParameter("codec", "opus,opuswb,opusuwb,opusswb");
        wobj.API_SetParameter("codec", "def");


        //Set number of frames per packet
        int framesPerPacket = 0;
        wobj.API_SetParameter("codecframecount", framesPerPacket);

        //Lowest loglevel for uncluttered console
        wobj.API_SetParameter("loglevel", 1);

        wobj.API_SetParameter("autoredial", 1);

        //test voor NAT problemen
        wobj.API_SetParameter("use_rport", 2);

        //Client automatically registers
        wobj.auto_register = 2;

        wobj.API_Start();
    }
}
