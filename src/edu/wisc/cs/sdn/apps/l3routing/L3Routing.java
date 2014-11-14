package edu.wisc.cs.sdn.apps.l3routing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.util.Host;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;

public class L3Routing implements IFloodlightModule, IOFSwitchListener, 
		ILinkDiscoveryListener, IDeviceListener, IL3Routing
{
	public static final String MODULE_NAME = L3Routing.class.getSimpleName();
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;
    
    private int INFINITY = 1000000000;
    
    private boolean init = false;

	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		//TODO: Remove
		System.out.println( "Starting init" );
		
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
        
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
		//TODO: Remove
		System.out.println( "Starting startUp" );

		
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		
		/*********************************************************************/
	}
	
	/**
	 * Get the table in which this application installs rules.
	 */
	public byte getTable()
	{ return this.table; }
	
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
	
    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
	
    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }

    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
	@Override
	public void deviceAdded(IDevice device) 
	{
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null)
		{
			log.info(String.format("Host %s added", host.getName()));
			this.knownHosts.put(device, host);
			
			/*****************************************************************/
			/* TODO: Update routing: add rules to route to new host          */
			
			/*****************************************************************/
			
		}
	}

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		log.info(String.format("Host %s is no longer attached to a switch", 
				host.getName()));
		
		/*********************************************************************/
		/* TODO: Update routing: remove rules to route to host               */
		
		/*********************************************************************/
	}

	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));
		
		/*********************************************************************/
		/* TODO: Update routing: change rules to route to host               */
		
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
		/* TODO: Update routing: change routing rules for all hosts          */

		/*********************************************************************/
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		
		/*********************************************************************/
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
	{
		for (LDUpdate update : updateList)
		{
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst())
			{
				log.info(String.format("Link s%s:%d -> host updated", 
					update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else
			{
				log.info(String.format("Link s%s:%d -> %s:%d updated", 
					update.getSrc(), update.getSrcPort(),
					update.getDst(), update.getDstPort()));
			}
		}
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		
		/*********************************************************************/
	}

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) 
	{ 
		//TODO: Remove
		System.out.println( "Starting linkDiscoverUpdate with LDUpdate" );

		
		this.linkDiscoveryUpdate(Arrays.asList(update)); }
	
	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) 
	{ this.deviceAdded(device); }

	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device) 
	{ /* Nothing we need to do, since we're not using VLANs */ }
	
	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId) 
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
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
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) 
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) 
	{ return false; }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{
		Collection<Class<? extends IFloodlightService>> services =
					new ArrayList<Class<? extends IFloodlightService>>();
		services.add(IL3Routing.class);
		return services; 
	}

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ 
        Map<Class<? extends IFloodlightService>, IFloodlightService> services =
        			new HashMap<Class<? extends IFloodlightService>, 
        					IFloodlightService>();
        // We are the class that implements the service
        services.put(IL3Routing.class, this);
        return services;
	}

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> modules =
	            new ArrayList<Class<? extends IFloodlightService>>();
		modules.add(IFloodlightProviderService.class);
		modules.add(ILinkDiscoveryService.class);
		modules.add(IDeviceService.class);
        return modules;
	}
	
	private void bellmanFord( Host sourceHost ) {
		//pass in null if just re-calculating:
			//switchAdded, switchRemoved, linkDiscoveryUpdate
		//pass in host if adding/removing:
			//deviceAdded, deviceMoved, 
		
		//TODO: Remove
		System.out.println( "Starting bellmanFord" );

		//recalculate: deviceAdded, deviceMoved
		if ( sourceHost != null ){
			
			// init - add all switches to the switch list
			List<BFVertex> switches = new ArrayList<BFVertex>();
			//get list of switches
			IOFSwitch sourceSwitch= sourceHost.getSwitch();
			
			// init: set costs to infinity, but !source, set source 0
			//TODO: n-1 times?
			for (IOFSwitch tempSwitch: this.getSwitches().values()) {
				
				BFVertex tmpVertex = new BFVertex();
				if (tempSwitch.equals(sourceSwitch)){
					tmpVertex = new BFVertex(tempSwitch, 0);
				}
			
				else{
					tmpVertex = new BFVertex(tempSwitch, INFINITY);
				}
				
				switches.add(tmpVertex);
			}//end for each loop

			//store the immNeighbers for every switch
			for (BFVertex neigh: switches) {
				for (int port: neigh.getSwitch().getEnabledPortNumbers()) {
					for (Link link: this.getLinks()) {
						if (link.getSrc() == port) {
							for (BFVertex vertex: switches) {
								if (vertex.getSwitch().getEnabledPortNumbers().
										contains(link.getDst())) {
									neigh.addImmNeighbor(port, neigh);
									break;

								}
							}
						}
					}
				}
			}
			
			//Relax weights??? -- unsure
				//recalculate costs to each dest from source
				//for (BFVertex source: switches){
					//for each port, compare weight of source to all neighs
					//for(int port: source.getSwitch().getEnabledPortNumbers()){
						//BFVertex immNeigh = source.getImmNeighbors().get(port);
						//if neigh has less cost go through that neigh
						
						//if (source.getCost() > immNeigh.getCost() + 1) {
							//source.setCost (immNeigh.getCost() + 1);
							//source.SetPortOut(port);
						//}
					//}
				//}
		}//end !null check
		
		//re-checking
		else {
			
			List<BFVertex> switches = new ArrayList<BFVertex>();

			// init switches
			for (IOFSwitch currSw: this.getSwitches().values()) {
				BFVertex tempVertex = new BFVertex();
				tempVertex = new BFVertex(currSw, INFINITY);
				switches.add(tempVertex);
			}
			
			//store the immNeighbers for every switch
			for (BFVertex neigh: switches) {
				for (int port: neigh.getSwitch().getEnabledPortNumbers()) {
					for (Link link: this.getLinks()) {
						if (link.getSrc() == port) {
							for (BFVertex vertex: switches) {
								if (vertex.getSwitch().getEnabledPortNumbers().
										contains(link.getDst())) {
									neigh.addImmNeighbor(port, neigh);
									break;

								}
							}
						}
					}
				}
			}
			
			for (BFVertex source : switches){
				
				IOFSwitch srcSwitch = source.getSwitch();
				
				// re-check weights for each
				for (IOFSwitch tmpSwitch : this.getSwitches().values()) {
					BFVertex tempVertex = new BFVertex();
					if (tmpSwitch.equals(srcSwitch)){
						tempVertex = new BFVertex(tmpSwitch, 0);
					}
				else{
					tempVertex = new BFVertex(tmpSwitch, INFINITY);
				}
					
				switches.add(tempVertex);
				
				}//end for each loop tmpSwitch
				
				
				//relax weights????
					//go through all links and recalculate costs to every dest from source
					//for (BFVertex source: switches)
						//compare weight to all neighs
						//if neigh.cost < currNeigh, go through that neighbor
						//for (int port: source.getImmSwitch().getEnabledPortNumbers())
				
				//iterate through all hosts of curr switch source, make new path
				//for (Host host: this.getHosts()){
				//}
				
			
			}//end for each loop source
		}//end else
		
		
		/*
		 * Use Bellman-Ford algorithm to build tables!
		 * Passed in sourceHost so we know where to start
		 * Things to remember about Bellman-Ford:
		 *  - Iterate V - 1 times bwhere V is the number of hosts
		 *  - all are distance to host from source host
		 */
		
			//TODO: uncomment?
		/*Collection<Host> hosts = getHosts();
		Map<Long, IOFSwitch> switches = getSwitches();
		Collection<Link> links = getLinks();
		int hostCount = hosts.size();*/
		
		//Implement Bellman-Ford with hostCount-1 iterations
		/*for( int iteration = 0; iteration < hostCount; iteration++ ) {
			for( Host currentHost : hosts ) {
				
			}
		}*/
	}//end BF func
	
	
	private void printData() {
		System.out.println( "Hosts: " + getHosts().toString() );
		System.out.println( "Switches: " + getSwitches().toString() );
		System.out.println( "Links: " + getLinks().toString() );
	}
}
