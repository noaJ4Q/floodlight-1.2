package net.floodlightcontroller.portscanner;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageFilterManagerService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import net.floodlightcontroller.core.IFloodlightProviderService;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.Set;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

import net.floodlightcontroller.packet.TCP;

import net.floodlightcontroller.routing.ForwardingBase;
import net.floodlightcontroller.routing.IRoutingDecision;


public class PortScanner_RateLimiter extends ForwardingBase implements IOFMessageFilterManagerService,
        IOFMessageListener, IFloodlightModule {


    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;
    protected static FileHandler fh;
    protected static SimpleFormatter formatter = new SimpleFormatter();


    public static Map<String,HashMap<String,Integer>> horizscan=new HashMap<String, HashMap<String ,Integer>>();
    public static Map<String,HashMap<String,Integer>> vertiscan=new HashMap<String, HashMap<String ,Integer>>();
    final int threshold =5;

    String fileName = "temp1.txt";
    BufferedWriter bufferedWriter;
    FileWriter fileWriter;

    protected  void createMatchFromPacket(IOFSwitch sw, OFPort inPort, FloodlightContext cntx) {

        HashMap<String,Integer> temp=new HashMap<String, Integer>();
        try{
            fh = new FileHandler("/home/floodlight/PortScan.html",true);
            logger.addHandler(fh);
            fh.setFormatter(formatter);
            int count=0;
            Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

            if (eth.getEtherType() == EthType.IPv4) {
                IPv4 ip = (IPv4) eth.getPayload();
                IPv4Address srcIp = ip.getSourceAddress();
                IPv4Address dstIp = ip.getDestinationAddress();

                if (FLOWMOD_DEFAULT_MATCH_TRANSPORT) {
                    if (ip.getProtocol().equals(IpProtocol.TCP)) {
                        TCP tcp = (TCP) ip.getPayload();
                        int flags=tcp.getFlags();
                        System.out.println("From Port Scanner "+srcIp + "to Destn IPaddress:" + dstIp + " flags " + flags  );
                        try
                        {
                            if(flags==20)
                            {
                                logger.info("flags == 20");
                                if(vertiscan.containsKey(srcIp.toString()))
                                {
                                    temp=vertiscan.get(srcIp.toString());
                                    if(temp.containsKey(dstIp.toString()))
                                    {
                                        //logger.info(threshold.toString());
                                        count= temp.get(dstIp.toString());
                                        System.out.print(count);
                                        temp.put(dstIp.toString(), count+1);


                                        //logger.info(threshold.get(dstIp.toString()).toString());
                                        if(count > threshold)
                                        {
                                            String controllerMitigateURL = "http://localhost:8001";
                                            String switchDPID = "00:00:f2:20:f9:45:4c:4e"; // SW3 POR DEFECTO
                                            logger.info("VERTICAL SCAN DETECTED!!!: Attacker is " + dstIp + " Victim is  " + srcIp);

                                            try {
                                                URL obj = new URL(controllerMitigateURL+"/port_scanning/"+switchDPID+"/"+dstIp);
                                                HttpURLConnection con = (HttpURLConnection) obj.openConnection();

                                                con.setRequestMethod("GET");
                                                int responseCode = con.getResponseCode();
                                                if (responseCode == HttpURLConnection.HTTP_OK) {
                                                    log.info("REQUEST SENDED...");
                                                } else {
                                                    System.out.println("La solicitud GET no fue exitosa.");
                                                }
                                            } catch (IOException e) {
                                                log.info(e.getMessage());
                                            }

                                            logger.info("Firewall rule added to block the attacker "+dstIp );
                                        }
                                    }
                                    else
                                    {
                                        temp.put(dstIp.toString(), 1);
                                        vertiscan.put(srcIp.toString(),temp);
                                    }
                                }
                                else
                                {
                                    //logger.info("srcIP not in map");
                                    HashMap<String,Integer> attacker=new HashMap<String, Integer>();
                                    attacker.put(dstIp.toString(), 1);
                                    vertiscan.put(srcIp.toString(), attacker);
                                    //logger.info("added");
                                    System.out.println(vertiscan.size());
                                }
                                String srcPort = tcp.getSourcePort().toString();
                                if(horizscan.containsKey(srcPort)){
                                    temp=horizscan.get(srcPort.toString());
                                    //logger.info(threshold.toString());
                                    if(temp.containsKey(dstIp.toString()))
                                    {
                                        //logger.info(threshold.toString());
                                        count= temp.get(dstIp.toString());
                                        //System.out.print(count);
                                        temp.put(dstIp.toString(), count+1);

                                        //logger.info(threshold.get(dstIp.toString()).toString());
                                        if(count > threshold)
                                        {
                                            logger.info("HORIZONTAL SCAN DETECTED!!!: Attacker is " + dstIp + " Victim is  " + srcIp);
                                            String command = "curl -X POST -d {\"src-ip\":\"" + dstIp + "\",\"action\":\"DENY\"} http://localhost:8080/wm/firewall/rules/json";
                                            Process p = Runtime.getRuntime().exec(command);
                                            logger.info("Firewall rule added to block the attacker "+dstIp );
                                        }
                                    }
                                    else
                                    {
                                        temp.put(dstIp.toString(), 1);
                                        horizscan.put(srcPort, temp);
                                    }
                                }
                                else{
                                    //logger.info("srcPort not in map");
                                    HashMap<String,Integer> attacker=new HashMap<String, Integer>();
                                    attacker.put(dstIp.toString(), 1);
                                    horizscan.put(srcPort, attacker);
                                    //logger.info("added");
                                    System.out.println(horizscan.size());
                                }
                            }
                        }
                        catch(Exception e)
                        {
                            System.out.println(e.getMessage());
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
        catch (Exception ex){
            ex.printStackTrace();
        }
        finally{
            fh.close();
        }


    }

    public Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision, FloodlightContext cntx) {


        return Command.CONTINUE;
    }

    @Override
    public String getName() {
        return PortScanner_RateLimiter.class.getSimpleName();
    }


    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }



    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        // TODO Auto-generated method stub
        return null;
    }



    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        // TODO Auto-generated method stub
        return null;
    }



    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = Logger.getLogger("PortScanLog");

        System.out.println("PortScanner.........");

    }



    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

        try {
            // Assume default encoding.
            fileWriter =
                    new FileWriter(fileName);

            // Always wrap FileWriter in BufferedWriter.
            bufferedWriter =
                    new BufferedWriter(fileWriter);

            // Note that write() does not automatically
            // append a newline character.
            bufferedWriter.write("---------------------------------------------------------");
            bufferedWriter.newLine();
            bufferedWriter.write("Port Scanner Log File");
            bufferedWriter.newLine();
            bufferedWriter.write("---------------------------------------------------------");
            bufferedWriter.newLine();
            bufferedWriter.write("We are writing");
            bufferedWriter.write(" the text to the file.");
            bufferedWriter.close();
        }
        catch(IOException ex) {
            System.out.println(
                    "Error writing to file '"
                            + fileName + "'");
            // Or we could just do this:
            // ex.printStackTrace();
        }
    }


    @Override
    public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		/*Ethernet eth =
	                IFloodlightProviderService.bcStore.get(cntx,
	                                            IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

	        Long sourceMACHash = eth.getSourceMACAddress().getLong();
	       if (!macAddresses.contains(sourceMACHash)) {
	            macAddresses.add(sourceMACHash);
	            logger.info("MAC Address: {} seen on switch: {}",
	                    eth.getSourceMACAddress().toString(),
	                    sw.getId().toString());
	        }*/
        OFPacketIn pi = (OFPacketIn)msg;
        OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
        createMatchFromPacket(sw, inPort, cntx);
        return Command.CONTINUE;
    }

    @Override
    public String setupFilter(String sid, ConcurrentHashMap<String, String> f,
                              int deltaInMilliSeconds) {
        // TODO Auto-generated method stub
        return null;
    }

}