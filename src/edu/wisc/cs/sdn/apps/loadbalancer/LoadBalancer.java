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
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
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
import net.floodlightcontroller.packet.TCP;
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
	private static final byte TCP_FLAG_RST = 0x04;
	
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
		
			/**
			 * When a client wants to initiate a connection with the virtual IP, 
			 * it will need to determine the MAC address associated with the 
			 * virtual IP using ARP.  The client does not know the IP is virtual, 
			 * and since it’s not actually assigned to any host, your SDN 
			 * application must take responsibility for replying to these requests.
			 */
			case Ethernet.TYPE_ARP:
				//cases: ARP.OP_REQUEST(?) 
				System.out.println("Found TYPE_ARP");
				ARP ARPpkt = (ARP)ethPkt.getPayload();
				
				//It's a trap!
				// we're going to construct ARP replies
				if (ARPpkt.getOpCode() == ARP.OP_REQUEST) {
					
					//check if null?
					
					//made this function to handle ARP requests
					/**
					 * You can construct an ARP reply packet using the classes in
					 *  the net.floodlightcontroller.packet package. You can use 
					 *  the sendPacket(...) method in the SwitchCommands class 
					 *  to send the packet. 
					 */
					handleARPRequest(ethPkt, ARPpkt, pktIn, sw);
					
				}
				
				//it's a reply or something else ! 
				else if (ARPpkt.getOpCode() == ARP.OP_REPLY){
					//this shouldn't happen - WE construct replies...
					//TODO: remove - this is for testing purposes
					System.out.println( "Error: Received ARP Reply" );
				}
				//END ARP CASE
				break;
				
			//If !ARP - it could have come from server or client, heading to server/client! Probaby IPv4
			case Ethernet.TYPE_IPv4:

				IPv4 IPpkt = null;
				IPpkt = (IPv4)ethPkt.getPayload();
				//PROTOCOL_TCP (!SYN, then TCP reset? Edit: Answer, YES!)
				if (IPpkt.getProtocol() == IPv4.PROTOCOL_TCP){
					
					//cast as TCP packet type
					TCP TCPpkt = (TCP)IPpkt.getPayload();
					//TODO: handle TCP method
					//if !typeSYN, then TCP reset:
					/**
					 * When the controller receives these TCP packets, which are not TCP SYN packets, 
					 * it should construct and send a TCP reset. You can construct the packet using 
					 * the classes in the net.floodlightcontroller.packet package—this is the same 
					 * code we used for constructing packets in the last programming assignment
					 */
					if (TCPpkt.getFlags() != TCP_FLAG_SYN){

						//TODO: handle TCPReset method
						handleTCPReset(ethPkt, IPpkt, TCPpkt, pktIn, sw);
						
					}
					
					else if (TCPpkt.getFlags() == TCP_FLAG_SYN){
						
						//TODO: handleTCP method - this will add a TON of rules, ZOMG
						handleTCP(ethPkt, IPpkt, TCPpkt, pktIn, sw);
					}					
				}
				
				else {
					System.out.println( "IPv4, but not TCP ");
				}

				System.out.println("Found TYPE_IPv4");
				break;
				
			default: System.out.println("Error: Received packet neither ARP nor IPv4");
				
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
			match.setNetworkProtocol( OFMatch.IP_PROTO_TCP );
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
	
	/**
	 * Construct and send an ARP reply packet when a client requests the MAC address associated with a virtual IP
	 */
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
	
	/**
	 * Construct and send a TCP reset packet if the controller receives a TCP packet that is not a TCP SYN
	 */
	public void handleTCPReset(Ethernet ethPkt, IPv4 ipPkt, TCP TCPpkt, OFPacketIn pktIn, IOFSwitch sw){
		
		//TODO:  
		//TCP requires flags be set? 1. set flag to TCP_FLAG_RST
		//2. set target/sender protocol and hardware addresses
		//3. set ethernet pkt fields
		//4. send
		
		LoadBalancerInstance LBInstance;
		
		int virtualIP = ipPkt.getDestinationAddress();
		LBInstance = instances.get( virtualIP );
		
		// update TCP header
		TCPpkt.setSourcePort(TCPpkt.getDestinationPort());
		TCPpkt.setDestinationPort(TCPpkt.getSourcePort());
		TCPpkt.setFlags( (short)TCP_FLAG_RST );
		TCPpkt.setSequence( TCPpkt.getAcknowledge() );
		// "When a receiver advertises a window size of 0, the sender stops sending data and starts the persist timer."
		TCPpkt.setWindowSize( (short) 0 );
		TCPpkt.setChecksum( (short) 0 );
		TCPpkt.serialize();
		
		// update IP header
		ipPkt.setPayload( TCPpkt );
		int targetIPAddress = ipPkt.getSourceAddress();
		int sourceIPAddress = ipPkt.getDestinationAddress();
		ipPkt.setDestinationAddress( targetIPAddress );
		ipPkt.setSourceAddress( sourceIPAddress );
		ipPkt.setChecksum( (short) 0 );
		ipPkt.serialize();
		
		// update Ethernet header
		ethPkt.setPayload( ipPkt );
		byte[] targetMACAddress = ethPkt.getSourceMACAddress();
		byte[] sourceMACAddress = ethPkt.getDestinationMACAddress();
		ethPkt.setDestinationMACAddress( targetMACAddress ); 
		ethPkt.setSourceMACAddress( sourceMACAddress );  
		
		// Send that baby
		short outPort = (short)pktIn.getInPort();
		SwitchCommands.sendPacket( sw, outPort, ethPkt );
	}
	
	/**
	 *     Install rules in every switch to:
    		- Notify the controller when a client initiates a TCP connection with a virtual IP—we 
    		  cannot specify TCP flags in match criteria, so the SDN switch will notify the controller 
    		  of each TCP packet sent to a virtual IP which did not match a connection-specific rule (described below)
    		- Notify the controller when a client issues an ARP request for the MAC address associated with a virtual IP
    		- Match all other packets against the rules in the next table in the switch (described below)

			These rules should be installed when a switch joins the network.

    		Install connection-specific rules for each new connection to a virtual IP to:
    		- Rewrite the destination IP and MAC address of TCP packets sent from a client to the virtual IP
    		- Rewrite the source IP and MAC address of TCP packets sent from server to client

			Connection-specific rules should match packets on the basis of Ethernet type, source IP address, 
			 destination IP address, protocol, TCP source port, and TCP destination port. 
			Connection-specific rules should take precedence over the rules that send TCP packets to the 
			 controller, otherwise every TCP packet would be sent to the controller. Therefore, these 
			 rules should have a higher priority than the rules installed when a switch joins the network.  
			Also, we want connection-specific rules to be removed when a TCP connection ends, so 
			 connection-specific rules should have an idle timeout of 20 seconds.
			 
			"we install the rule to override destination MAC and destination IP for all the incoming packets from that source."
	 * 
	 */
	public void handleTCP(Ethernet ethPkt, IPv4 IPpkt, TCP TCPpkt, OFPacketIn pktIn, IOFSwitch sw){
		
		//likely need to resolve Virtual IP, so need LB Instance
		LoadBalancerInstance LBInstance;
		//TODO: handle TCP
		//1. need virtual IP/MAC of intended dest
		//TCPpkt is SYN - meaning we are init the connection between client/host - also used in setting IP/TCP pkt information
		int virtualIP = IPpkt.getDestinationAddress();
		LBInstance = instances.get(virtualIP);

		//2. use virtual IP/MAC to get real IP/MAC 
		byte[] virtualMAC = LBInstance.getVirtualMAC();
		// Resolve the host's virtual IP and MAC of the LB
		int hostIP = LBInstance.getNextHostIP();
		byte[] hostMAC = getHostMACAddress(hostIP);
		
		//3. set up the match criteria like before in L3routing - we need to set rules using them
		OFMatch matchCriteria = new OFMatch();
		
		//TODO: seperate into different methods?
		//3.a) set up the TCPpkt source/desk addresses
		//set the pkt type
		short TCPTransportDestinationAddress = TCPpkt.getDestinationPort();
		short TCPTransportSourceAddress = TCPpkt.getSourcePort();
		matchCriteria.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
		matchCriteria.setTransportDestination(OFMatch.IP_PROTO_TCP, TCPTransportDestinationAddress);
		matchCriteria.setTransportSource(OFMatch.IP_PROTO_TCP, TCPTransportSourceAddress);

		//TODO: seperate into different methods?
		//3.b) set up IPpkt source/dest addresses
		//set the pkt type
		short IPNetworkSourceAddress = (short)IPpkt.getSourceAddress();
		
		matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		matchCriteria.setNetworkDestination(OFMatch.ETH_TYPE_IPV4, virtualIP);
		matchCriteria.setNetworkSource(OFMatch.ETH_TYPE_IPV4, IPNetworkSourceAddress);
		
		//4. change the packets Action fields when it is send from client using the virutal IP to resolve
		//setting fields for IPv4
		OFActionSetField destinationIPAddress = new OFActionSetField(OFOXMFieldType.IPV4_DST, hostIP);
		OFActionSetField sourceIPAddress = new OFActionSetField(OFOXMFieldType.IPV4_SRC, virtualIP);
		//setting fields for ETH
		OFActionSetField destinationMACAddress = new OFActionSetField(OFOXMFieldType.ETH_DST, hostMAC);
		OFActionSetField sourceMACAddress = new OFActionSetField(OFOXMFieldType.ETH_SRC, virtualMAC);
		
		//5. set action list of pkt's fields
		List<OFAction> actionList = new ArrayList<OFAction>();
		actionList.add(destinationIPAddress);
		actionList.add(destinationMACAddress);
		actionList.add(sourceIPAddress);
		actionList.add(sourceMACAddress);

		//6. install rules?
		List<OFInstruction> listOFInstructions = Arrays.asList((OFInstruction)
				new	OFInstructionApplyActions().setActions(actionList),
				new OFInstructionGotoTable().setTableId(l3RoutingApp.getTable()));
		
		SwitchCommands.installRule(sw, table, (short)(SwitchCommands.DEFAULT_PRIORITY + 2),
		matchCriteria, listOFInstructions, (short)0, IDLE_TIMEOUT);
				
		//7. loop through every switch and do stuff?
				
				for( IOFSwitch currSwitch : floodlightProv.getAllSwitchMap().values() ) {
					
					matchCriteria = new OFMatch();

					matchCriteria.setNetworkProtocol( OFMatch.IP_PROTO_TCP );
					matchCriteria.setTransportDestination( OFMatch.IP_PROTO_TCP, TCPpkt.getSourcePort() );
					matchCriteria.setTransportSource( OFMatch.IP_PROTO_TCP, TCPpkt.getDestinationPort() );

					matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
					matchCriteria.setNetworkDestination(OFMatch.ETH_TYPE_IPV4, virtualIP);
					matchCriteria.setNetworkSource(OFMatch.ETH_TYPE_IPV4, hostIP);
					
					//setting fields for IPv4
					destinationIPAddress = new OFActionSetField(OFOXMFieldType.IPV4_DST, IPpkt.getSourceAddress() );
					sourceIPAddress = new OFActionSetField(OFOXMFieldType.IPV4_SRC, LBInstance.getVirtualIP() );
					// Set Ethernet Fields
					destinationMACAddress = new OFActionSetField(OFOXMFieldType.ETH_DST, ethPkt.getSourceMACAddress() );
					sourceMACAddress = new OFActionSetField(OFOXMFieldType.ETH_SRC, LBInstance.getVirtualMAC() );
					
					actionList = new ArrayList<OFAction>();
					actionList.add(destinationMACAddress);
					actionList.add(destinationIPAddress);
					actionList.add(sourceMACAddress);
					actionList.add(sourceIPAddress);
					
					listOFInstructions = Arrays.asList( (OFInstruction)
							new OFInstructionApplyActions().setActions( actionList ),
							new OFInstructionGotoTable().setTableId( l3RoutingApp.getTable() ) );
					
					SwitchCommands.installRule( currSwitch, table, (short)(SwitchCommands.DEFAULT_PRIORITY + 2),
							matchCriteria, listOFInstructions, (short)0, IDLE_TIMEOUT );

				}
	}
	
		
	
	
}
