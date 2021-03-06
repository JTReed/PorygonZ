package edu.wisc.cs.sdn.apps.l3routing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.util.Host;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;

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
		ILinkDiscoveryListener, IDeviceListener, IL3Routing {
	public static final String MODULE_NAME = L3Routing.class.getSimpleName();
	public static final int INFINITY = 9999;

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
	private Map<IDevice, Host> knownHosts;

	/**
	 * Loads dependencies and initializes data structures.
	 */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO: Remove
		System.out.println("Starting init");

		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String, String> config = context.getConfigParams(this);
		this.table = Byte.parseByte(config.get("table"));

		this.floodlightProv = context
				.getServiceImpl(IFloodlightProviderService.class);
		this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
		this.deviceProv = context.getServiceImpl(IDeviceService.class);

		this.knownHosts = new ConcurrentHashMap<IDevice, Host>();
	}

	/**
	 * Subscribes to events and performs other startup tasks.
	 */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO: Remove
		System.out.println("Starting startUp");

		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
	}

	/**
	 * Get the table in which this application installs rules.
	 */
	public byte getTable() {
		return this.table;
	}

	/**
	 * Get a list of all known hosts in the network.
	 */
	private Collection<Host> getHosts() {
		return this.knownHosts.values();
	}

	/**
	 * Get a map of all active switches in the network. Switch DPID is used as
	 * the key.
	 */
	private Map<Long, IOFSwitch> getSwitches() {
		return floodlightProv.getAllSwitchMap();
	}

	/**
	 * Get a list of all active links in the network.
	 */
	private Collection<Link> getLinks() {
		return linkDiscProv.getLinks().keySet();
	}

	/**
	 * Event handler called when a host joins the network.
	 * 
	 * @param device
	 *            information about the host
	 */
	@Override
	public void deviceAdded(IDevice device) {
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null) {
			log.info(String.format("Host %s added", host.getName()));
			this.knownHosts.put(device, host);

			bellmanFord(host);
		}
	}

	/**
	 * Event handler called when a host is no longer attached to a switch.
	 * 
	 * @param device
	 *            information about the host
	 */
	@Override
	public void deviceRemoved(IDevice device) {
		Host host = this.knownHosts.get(device);
		if (null == host) {
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}

		log.info(String.format("Host %s is no longer attached to a switch",
				host.getName()));

		removeRules(host);

	}

	/**
	 * Event handler called when a host moves within the network.
	 * 
	 * @param device
	 *            information about the host
	 */
	@Override
	public void deviceMoved(IDevice device) {
		Host host = this.knownHosts.get(device);
		if (null == host) {
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}

		if (!host.isAttachedToSwitch()) {
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(), host
				.getSwitch().getId(), host.getPort()));

		removeRules(host);
		bellmanFord(host);

	}

	/**
	 * Event handler called when a switch joins the network.
	 * 
	 * @param DPID
	 *            for the switch
	 */
	@Override
	public void switchAdded(long switchId) {
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));

		removeAllRules();
		bellmanFord();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * 
	 * @param DPID
	 *            for the switch
	 */
	@Override
	public void switchRemoved(long switchId) {
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));

		for (Host host : getHosts()) {
			if (host.getSwitch() != null && host.getSwitch().equals(sw)) {
				removeRules(host);
			}
		}

		// K - call BF to recalculate/add rules
		bellmanFord();
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * 
	 * @param updateList
	 *            information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) {
		for (LDUpdate update : updateList) {
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst()) {
				log.info(String.format("Link s%s:%d -> host updated",
						update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else {
				log.info(String.format("Link s%s:%d -> %s:%d updated",
						update.getSrc(), update.getSrcPort(), update.getDst(),
						update.getDstPort()));
			}
		}
		
		//removeAllRules();
		bellmanFord();
	}

	/**
	 * Event handler called when link goes up or down.
	 * 
	 * @param update
	 *            information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) {
		// TODO: Remove
		System.out.println("Starting linkDiscoverUpdate with LDUpdate");

		this.linkDiscoveryUpdate(Arrays.asList(update));
	}

	/**
	 * Event handler called when the IP address of a host changes.
	 * 
	 * @param device
	 *            information about the host
	 */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) {
		this.deviceAdded(device);
	}

	/**
	 * Event handler called when the VLAN of a host changes.
	 * 
	 * @param device
	 *            information about the host
	 */
	@Override
	public void deviceVlanChanged(IDevice device) { /*
													 * Nothing we need to do,
													 * since we're not using
													 * VLANs
													 */
	}

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * 
	 * @param DPID
	 *            for the switch
	 */
	@Override
	public void switchActivated(long switchId) { /*
												 * Nothing we need to do, since
												 * we're not switching
												 * controller roles
												 */
	}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * 
	 * @param DPID
	 *            for the switch
	 */
	@Override
	public void switchChanged(long switchId) { /* Nothing we need to do */
	}

	/**
	 * Event handler called when a port on a switch goes up or down, or is added
	 * or removed.
	 * 
	 * @param DPID
	 *            for the switch
	 * @param port
	 *            the port on the switch whose status changed
	 * @param type
	 *            the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) { /*
									 * Nothing we need to do, since we'll get a
									 * linkDiscoveryUpdate event
									 */
	}

	/**
	 * Gets a name for this module.
	 * 
	 * @return name for this module
	 */
	@Override
	public String getName() {
		return this.MODULE_NAME;
	}

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) {
		return false;
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) {
		return false;
	}

	/**
	 * Tell the module system which services we provide.
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> services = new ArrayList<Class<? extends IFloodlightService>>();
		services.add(IL3Routing.class);
		return services;
	}

	/**
	 * Tell the module system which services we implement.
	 */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> services = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		// We are the class that implements the service
		services.put(IL3Routing.class, this);
		return services;
	}

	/**
	 * Tell the module system which modules we depend on.
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> modules = new ArrayList<Class<? extends IFloodlightService>>();
		modules.add(IFloodlightProviderService.class);
		modules.add(ILinkDiscoveryService.class);
		modules.add(IDeviceService.class);
		return modules;
	}

	private void addLinks(BFNode node) {

	}

	/**
	 * Finds the shortest paths from host to host and installs rules in the flow
	 * tables
	 * 
	 */
	private void bellmanFord() {
		/*
		 * Use Bellman-Ford algorithm to build tables! Passed in sourceHost so
		 * we know where to start Things to remember about Bellman-Ford: -
		 * Iterate V - 1 times where V is the number of nodes - all are distance
		 * to host from source host
		 */

		for (Host host : getHosts()) {
			bellmanFord(host);
		}
	}

	/**
	 * Finds shortest path from a source host to every other host and installs
	 * rules in flow tables
	 * 
	 * @param srcHost
	 *            host to find shortest distances from
	 */
	private void bellmanFord(Host sourceHost) {
		List<BFNode> switchTopo = new ArrayList<BFNode>();
		IOFSwitch sourceSwitch = sourceHost.getSwitch();
		BFNode sourceNode = null;

		// add switches to switchTopo
		for (IOFSwitch iofSwitch : getSwitches().values()) {
			BFNode node = null;
			if (iofSwitch.equals(sourceSwitch)) {
				node = new BFNode(iofSwitch, 0);
				sourceNode = node;
			} else {
				node = new BFNode(iofSwitch, INFINITY);
			}
			switchTopo.add(node);
		}
		setupBFLinks(switchTopo);

		// Run Bellman-Ford for V - 1 iterations where V is the number of
		// switches
		// based on <http://algs4.cs.princeton.edu/44sp/BellmanFordSP.java.html>
		// we see that order doesn't matter
		IOFSwitch currentSwitch = null;
		// System.out.println( "Source: Switch " + sourceSwitch.getId() );
		for (int i = 0; i < switchTopo.size() - 1; i++) {
			for (BFNode node : switchTopo) {
				currentSwitch = node.getSwitch();
				// if(i == switchTopo.size() - 2 ) System.out.print("  Switch "
				// + currentSwitch.getId() + ": " );
				// for each port on that node
				for (int port : currentSwitch.getEnabledPortNumbers()) {

					// change weight and best port if the path is better
					if (node.getLinkedNodes().get(port) != null
							&& node.getDistance() > node.getLinkedNodes()
									.get(port).getDistance() + 1) {
						node.setDistance(node.getLinkedNodes().get(port)
								.getDistance() + 1);
						node.setBestPort(port);
					}
				}
				if (i == switchTopo.size() - 2) {
					// System.out.print(node.getDistance() + " Hops back to " +
					// sourceSwitch.getId() + " through port " +
					// node.getBestPort() + " " );
					// System.out.println("");
				}

			}
		}

		// now install instructions!
		for (Host host : getHosts()) {
			if (host.getSwitch() != null
					&& host.getSwitch().equals(sourceSwitch)) {
				for (BFNode destNode : switchTopo) {
					if (destNode != sourceNode) {
						OFInstructionApplyActions instructions = new OFInstructionApplyActions();

						// create new option with outgoing port
						OFActionOutput action = new OFActionOutput();
						action.setPort(destNode.getBestPort());

						// add action to list of rules
						List<OFAction> rules = new ArrayList<OFAction>();
						rules.add(action);
						instructions.setActions(rules);

						OFMatch match = new OFMatch();

						// TODO: IPv4 necessary?
						match.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
						match.setNetworkDestination(host.getIPv4Address());

						List<OFInstruction> instructionList = Arrays
								.asList((OFInstruction) new OFInstructionApplyActions()
										.setActions(rules));
						if (!SwitchCommands.installRule(destNode.getSwitch(),
								table, SwitchCommands.DEFAULT_PRIORITY, match,
								instructionList)) {
							System.out
									.println("CRISIS ALERT, RULE NOT INSTALLED CORRECTLY");
							return;
						}
					} else {
						// add rule to get to this host from the source node
						OFInstructionApplyActions instructions = new OFInstructionApplyActions();

						// create new option with outgoing port
						OFActionOutput action = new OFActionOutput();
						action.setPort(host.getPort());

						// add action to list of rules
						List<OFAction> rules = new ArrayList<OFAction>();
						rules.add(action);
						instructions.setActions(rules);

						OFMatch match = new OFMatch();

						// TODO: IPv4 necessary?
						match.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
						match.setNetworkDestination(host.getIPv4Address());

						List<OFInstruction> instructionList = Arrays
								.asList((OFInstruction) new OFInstructionApplyActions()
										.setActions(rules));
						if (!SwitchCommands.installRule(destNode.getSwitch(),
								table, SwitchCommands.DEFAULT_PRIORITY, match,
								instructionList)) {
							System.out
									.println("CRISIS ALERT, RULE NOT INSTALLED CORRECTLY");
							return;
						}
					}
				}
			}
		}
	}

	/**
	 * Sets each BFNode's linked nodes in the network topology
	 * 
	 * @param switchTopo
	 *            The list of BFNodes that makes up the network topolpgy
	 */
	private void setupBFLinks(List<BFNode> switchTopo) {
		IOFSwitch currSwitch = null;
		IOFSwitch targetSwitch = null;

		// loop through each BFNode
		for (BFNode node : switchTopo) {
			// get the switch
			currSwitch = node.getSwitch();

			// loop through each port on the switch
			for (int port : currSwitch.getEnabledPortNumbers()) {
				// find any links with that port as the source
				for (Link link : getLinks()) {
					// check if link starts at this switch
					if (link.getSrc() == currSwitch.getId()
							&& link.getSrcPort() == port) {
						// loop through BFNodes again to see where to go
						for (BFNode targetNode : switchTopo) {
							targetSwitch = targetNode.getSwitch();

							// check if we have the correct BFNode here
							if (targetSwitch.getId() == link.getDst()
									&& targetSwitch.getEnabledPortNumbers()
											.contains(link.getDstPort())) {
								node.addLinkedNode(port, targetNode);
								break; // move on to next link
							}
						}
					}
				}
			}
		}
	}

	/**
	 * remove all the rules with host as a destination from each switch
	 * 
	 * @param host
	 */
	private void removeRules(Host host) {
		OFMatch match = new OFMatch();
		match.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		match.setNetworkDestination(host.getIPv4Address());

		for (IOFSwitch swtch : getSwitches().values()) {
			if (!SwitchCommands.removeRules(swtch, table, match)) {
				System.out.println("could not remove rule for some reason");
			}
		}
	}

	/**
	 * remove every rule from each switch
	 */
	private void removeAllRules() {
		for (Host host : getHosts()) {
			removeRules(host);
		}
	}

	/**
	 * Prints the number of hosts, switches, and links in the network
	 */
	private void printData() {
		System.out.println("Hosts: " + getHosts().size());
		System.out.println("Switches: " + getSwitches().size());
		System.out.println("Links: " + getLinks().size());
	}
}
