import webphone.webphone;

public class Caller extends Thread{
    webphone wobj;
    boolean startCall = false;

    void startCall(){
        startCall = true;
    }

    void endCall(){
        wobj.API_Stop();
        wobj.API_Exit();
    }

    boolean isRegistered(){
        return wobj.API_IsRegistered();
    }

    void createWebphone(String serverAddress, String username, String password){
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
        wobj.API_SetParameter("rtpstat", 1);

        //Set option to use RTCP
        wobj.API_SetParameter("rtcp", true);

        //TODO: andere codecs?
        //Set option to use Opus codec
        wobj.API_SetParameter("codec", "opus,opuswb,opusuwb,opusswb");

        //Set number of frames per packet
        int framesPerPacket = 0;
        wobj.API_SetParameter("codecframecount", framesPerPacket);

        //Lowest loglevel for uncluttered console
        wobj.API_SetParameter("loglevel", 1);

        //Client automatically registers
        wobj.auto_register = 2;

        wobj.API_Start();
    }

    public void run(String target) {
        wobj.API_Call(-1, target);
    }
}
