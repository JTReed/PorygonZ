package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFActionOutput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.l3routing.IL3Routing;
import edu.wisc.cs.sdn.apps.util.ArpServer;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.util.MACAddress;

import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Interface to L3Routing application
    private IL3Routing l3RoutingApp;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;
    

    private static final int NON_ARP_RULE = 1;
    private static final int ARP_RULE = 2;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        this.l3RoutingApp = context.getServiceImpl(IL3Routing.class);
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
        
        /*********************************************************************/
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		
		/*********************************************************************/
	}
	
	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		/*********************************************************************/
		/* TODO: Install rules to send:                                      */
		/*       (1) packets from new connections to each virtual load       */
		/*       balancer IP to the controller                               */
		/*       (2) ARP packets to the controller, and                      */
		/*       (3)  	all other packets to the next rule table in the switch  */
		
		

		//for every LB inst., edit pkt info and send back to controller
		for (LoadBalancerInstance LBInstance: this.instances.values()){
			
			//add the rule (case 1) for client
			addRule(sw, LBInstance, NON_ARP_RULE);
			//add the rule for ARP (case 2) since we know the information
			addRule(sw, LBInstance, ARP_RULE);
			
			
		}
		
		//pkts should go to the level-3 routing table
		OFMatch match = new OFMatch(); 
		List<OFInstruction> listOFInstructions;
		listOFInstructions = Arrays.asList((OFInstruction)new OFInstructionGotoTable().setTableId(l3RoutingApp.getTable()));
		SwitchCommands.installRule(sw, this.table, (short)(SwitchCommands.DEFAULT_PRIORITY),
									match, listOFInstructions);
		
		
		/*********************************************************************/
	}
	
	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0,
				pktIn.getPacketData().length);
		
		/*********************************************************************/
		/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
		/*       SYNs sent to a virtual IP, select a host and install        */
		/*       connection-specific rules to rewrite IP and MAC addresses;  */
		/*       for all other TCP packets sent to a virtual IP, send a TCP  */
		/*       reset; ignore all other packets                             */
		
		short type = ethPkt.getEtherType();
		
		switch(type){
			case Ethernet.TYPE_ARP:
				//cases: ARP.OP_REQUEST(?) 
				System.out.println("Found TYPE_ARP");
				ARP ARPpkt = (ARP)ethPkt.getPayload();
				
				//It's a trap!
				// we're going to construct ARP replies
				if (ARPpkt.getOpCode() == ARP.OP_REQUEST) {
					
					//made this function to handle ARP requests
					handleARPRequest(ethPkt, ARPpkt, pktIn, sw);
					
				}
				
				//it's a reply or something else ! 
				else if (ARPpkt.getOpCode() == ARP.OP_REPLY){
					//this shouldn't happen - WE construct replies...
					//TODO: remove - this is for testing purposes
					System.out.println( "Something is terribly wrong here" );
				}
				//END ARP CASE
				
			//If !ARP - it should have come from server heading to client! Probaby IPv4
			case Ethernet.TYPE_IPv4:

				IPv4 ipPacket = null;
				ipPacket = (IPv4)ethPkt.getPayload();
				//PROTOCOL_TCP (!SYN, then TCP reset?)
				//SYN packet-init conenction
					//SYN Packet Reply
					//SYN Packet Send
				System.out.println("Found TYPE_IPv4");
			default: System.out.println("Frick if I know what happened");
				
		}
		
		
		
		
		/*********************************************************************/
		
		return Command.CONTINUE;
	}
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
	
	
	/**
	 * adds rule to table taking in switch, the LB Instance, and an int for type
	 * @type = 1: general routing rule (TCP, TDP, IPv4)
	 * @type = 2: ARP routing rule
	 */
	public void addRule(IOFSwitch sw, LoadBalancerInstance LBInstance, int type){
		OFActionOutput act;
		List<OFAction> listOFActions;
		OFInstructionApplyActions instruct;
		OFMatch match;
		List<OFInstruction> listOFInstructions;
		
		act = new OFActionOutput();
		act.setPort(OFPort.OFPP_CONTROLLER);
		listOFActions= new ArrayList<OFAction>();
		listOFActions.add(act);
		instruct = new OFInstructionApplyActions();
		instruct.setActions(listOFActions);
		match= new OFMatch();

		if (type == NON_ARP_RULE){
			match.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
			match.setNetworkDestination(OFMatch.ETH_TYPE_IPV4, LBInstance.getVirtualIP());
			match.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
			listOFInstructions = Arrays.asList((OFInstruction)new OFInstructionApplyActions().setActions(listOFActions));
			SwitchCommands.installRule(sw, this.table, (short)(SwitchCommands.DEFAULT_PRIORITY + 1),
						match, listOFInstructions);
		}
		
		if (type == ARP_RULE){
			
			match.setDataLayerType(OFMatch.ETH_TYPE_ARP);
			match.setNetworkDestination(OFMatch.ETH_TYPE_ARP, LBInstance.getVirtualIP());
			//set network prot?
			
			listOFInstructions = Arrays.asList((OFInstruction)new OFInstructionApplyActions().setActions(listOFActions));
			SwitchCommands.installRule(sw, this.table, (short)(SwitchCommands.DEFAULT_PRIORITY + 1),
			match, listOFInstructions);	
		}
		
	}
	
	/*public void addARPRule(IOFSwitch sw, LoadBalancerInstance LBInstance){
		OFActionOutput act;
		List<OFAction> listOFActions;
		OFInstructionApplyActions instruct;
		OFMatch match;
		List<OFInstruction> listOFInstructions;
		
		act = new OFActionOutput();
		act.setPort(OFPort.OFPP_CONTROLLER);
		listOFActions = new ArrayList<OFAction>();
		listOFActions.add(act);
		instruct = new OFInstructionApplyActions();
		instruct.setActions(listOFActions);
		
		match = new OFMatch();
		match.setDataLayerType(OFMatch.ETH_TYPE_ARP);
		match.setNetworkDestination(OFMatch.ETH_TYPE_ARP, LBInstance.getVirtualIP());
		//set network prot?
		
		listOFInstructions = Arrays.asList((OFInstruction)new OFInstructionApplyActions().setActions(listOFActions));
		SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + 1),
		match, listOFInstructions);	
		
	}*/
	
	public void handleARPRequest(Ethernet ethPkt, ARP ARPpkt, OFPacketIn pktIn, IOFSwitch sw){
		

		//need LBInstance object to get LB instance from MAP<instances, int vitualIP> so we can get Virtual MAC for ARPpkt
		LoadBalancerInstance LBInstance;
		
		//but we should probs:
			//get infor to send reply: note: SwitchCommands.java holds methods to send pkt
		
				//1. need virtual IP of intended dest
				//get target address: 
				byte[] targetAddress = ARPpkt.getTargetProtocolAddress();
				//cast byte array as IPv4 address: 
				int virtualIP = IPv4.toIPv4Address(targetAddress);
					
				//2. MAP of <instances, virtIP>: use virtual IP to get the LB instance associated, used to get VirtMAC
				LBInstance = instances.get(virtualIP);
					
				//3. we need to swap sender and dest fields to send back to requester - so get information needed
				//TODO: add these to the set methods below, currently seperated for understanding
				//get client's protocol address - will be ARPreply's target protocol add
				byte[] targetProtocolAddress = ARPpkt.getSenderProtocolAddress();
				//get client's hardware address - will be ARPreply's target Hrdwr Add
				byte[] targetHardwareAddress = ARPpkt.getSenderHardwareAddress();
				//use virtual IP to get it's IPv4 address - will be sender's Protocol Address
				byte[] senderProtocolAddress = IPv4.toIPv4AddressBytes(virtualIP);
				//get virtual MAC from LB instance we found from VIRTual IP in (2) - will be sender's Hardware Add
				byte[] senderHardwareAddress = LBInstance.getVirtualMAC();
				//get eth pkt's curr source MAC address - will be destMACAddress for eth pkt
				byte[] destMACAddress = ethPkt.getSourceMACAddress();
				
				//4. we need to swap, so set pkt's fields from (3):
				ARPpkt.setOpCode(ARP.OP_REPLY);
				ARPpkt.setTargetProtocolAddress(targetProtocolAddress);
				ARPpkt.setTargetHardwareAddress(targetHardwareAddress);
				ARPpkt.setSenderProtocolAddress(senderProtocolAddress);
				ARPpkt.setSenderHardwareAddress(senderHardwareAddress);
					
				//5. set ethernet pkt fields so it routes to correct dest (source and MAC address need to be changed)
				ethPkt.setPayload(ARPpkt);
				ethPkt.setDestinationMACAddress( destMACAddress );
				//use same senderHardwareAddress? I can't imagine not...
				ethPkt.setSourceMACAddress( senderHardwareAddress );
					
				//6. done with building ARPpkt, so send it off!
				//outSw is sw, outPort is pkt's inPort (what the request to control is called), ethpkt is ethpkt
				short outPort = (short)pktIn.getInPort();
				SwitchCommands.sendPacket( sw, outPort, ethPkt );
		
		
	}
		
	
	
}
