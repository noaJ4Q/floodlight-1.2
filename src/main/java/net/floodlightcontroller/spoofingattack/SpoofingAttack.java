package net.floodlightcontroller.spoofingattack;
import java.util.*;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import
        net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.IPv4;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.*;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.concurrent.ConcurrentSkipListSet;
import net.floodlightcontroller.packet.Ethernet;
import org.sdnplatform.sync.internal.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
public class SpoofingAttack implements IOFMessageListener,
        IFloodlightModule{
    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;
    protected IDeviceService deviceService ;
    @Override
    public String getName() {
        return "Intranetattack";
    }
    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }
    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return (type.equals(OFType.PACKET_IN) &&
                (name.equals("forwarding")));
    }
    @Override
    public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
//se obtiene la ipv4 del
        if (eth.getEtherType().equals(EthType.IPv4)) {
            /* We got an IPv4 packet; get the payload from Ethernet */
            IPv4 ipv4 = (IPv4) eth.getPayload();
            MacAddress macAddress = eth.getSourceMACAddress();
            for (Iterator<? extends IDevice> it = deviceService.queryDevices(macAddress, VlanVid.ZERO,
                         ipv4.getSourceAddress(), IPv6Address.NONE, DatapathId.NONE,
                         OFPort.ZERO); it.hasNext(); ) {
                IDevice device = it.next();
                for (IPv4Address i : device.getIPv4Addresses()){
                    System.out.println(ipv4.getSourceAddress());
                    if(i!=ipv4.getSourceAddress()){
                        return Command.STOP;
                    }
                }
            }
/* ArrayList<String> listaipv4 = new ArrayList<>();
System.out.println(listaipv4.size());
int bandera = listaipv4.size();
listaipv4.add(userA);
System.out.println("Cantidad de elementos: ");
System.out.println(listaipv4.size());
System.out.println(userA);
for(int i = 0; i<=bandera; i++){
for(int j = 0; j<=bandera; j++){
if(Objects.equals(listaipv4.get(i),
listaipv4.get(j))){
System.out.println(listaipv4.get(i));
System.out.println(listaipv4.get(j));
return Command.STOP;
}
}
}
*/
        } return Command.CONTINUE;
    }
    @Override
    public Collection<Class<? extends IFloodlightService>>
    getModuleServices() {
        return null;
    }
    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService>
    getServiceImpls() {
        return null;
    }
    @Override
    public Collection<Class<? extends IFloodlightService>>
    getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = new
                ArrayList<Class<? extends IFloodlightService>>();
        l.add(IDeviceService.class);
        return l;
    }
    @Override
    public void init(FloodlightModuleContext context) throws
            FloodlightModuleException {
        floodlightProvider =
                context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = LoggerFactory.getLogger(SpoofingAttack.class);
        deviceService = context.getServiceImpl(IDeviceService.class);
    }
    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
}