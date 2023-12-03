package net.floodlightcontroller.portscanner;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.SynchronousQueue;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.VlanVid;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageFilterManagerService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
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


public class PortScanner extends ForwardingBase implements IOFMessageFilterManagerService,
        IOFMessageListener, IFloodlightModule {



    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;
    protected static FileHandler fh;
    protected static SimpleFormatter formatter = new SimpleFormatter();


    public static Map<String,HashMap<String,Integer>> horizscan=new HashMap<String, HashMap<String ,Integer>>();
    public static Map<String,HashMap<String,Integer>> vertiscan=new HashMap<String, HashMap<String ,Integer>>();
    final int threshold =5;

    protected  void createMatchFromPacket(IOFSwitch sw, OFPort inPort, FloodlightContext cntx) {
        HashMap<String,Integer> temp=new HashMap<String, Integer>();
        try{
            fh = new FileHandler("/home/floodlight/PortScan.html",true);
            logger.addHandler(fh);
            fh.setFormatter(formatter);
            int count=0;

            // The packet in match will only contain the port number.
            // We need to add in specifics for the hosts we're routing between.

            Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

            // TODO Detect switch type and match to create hardware-implemented flow

            if (eth.getEtherType() == EthType.IPv4) {
                //logger.info(eth.getPayload().toString());
                /* shallow check for equality is okay for EthType */
                IPv4 ip = (IPv4) eth.getPayload();
                IPv4Address srcIp = ip.getSourceAddress();
                IPv4Address dstIp = ip.getDestinationAddress();

                if (FLOWMOD_DEFAULT_MATCH_TRANSPORT) {
                    /*
                     * Take care of the ethertype if not included earlier,
                     * since it's a prerequisite for transport ports.
                     */
                    if (ip.getProtocol().equals(IpProtocol.TCP)) {
                        TCP tcp = (TCP) ip.getPayload();
                        int flags=tcp.getFlags();
                        logger.info("From Port Scanner "+srcIp + "to Destn IPaddress:" + dstIp + "flags " + flags  );
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
                                        if(count > threshold) logger.info("VERTICAL SCAN DETECTED!!!: Attacker is " + dstIp + " Victim is  " + srcIp);
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
                                        if(count > threshold) logger.info("HORIZONTAL SCAN DETECTED!!!: Attacker is " + dstIp + " Victim is  " + srcIp);
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
        return PortScanner.class.getSimpleName();
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

    }



    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
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