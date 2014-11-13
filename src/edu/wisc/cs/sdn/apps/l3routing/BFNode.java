package edu.wisc.cs.sdn.apps.l3routing;

import java.util.Map;
import java.util.HashMap;
import net.floodlightcontroller.core.IOFSwitch;

public class BFNode {
	private IOFSwitch iofSwitch;
	private int distance;
	private int bestPort;
	private HashMap<Integer, BFNode> linkedNodes;
	
	public BFNode() 
	{
		this.iofSwitch = null;
		this.distance = 0;
		this.bestPort = -1;
		this.linkedNodes = new HashMap<Integer, BFNode>();
	}
	
	public BFNode( IOFSwitch sw, int dist )
	{
		this.iofSwitch = sw;
		this.distance = dist;
		this.bestPort = -1;
		this.linkedNodes = new HashMap<Integer, BFNode>();
	}
	
	public void setSwitch(IOFSwitch sw) 
	{
		this.iofSwitch = sw;
	}
	
	public void setDistance( int dist )
	{
		this.distance = dist;
	}
	
	public void setBestPort( int port )
	{
		this.bestPort = port;;
	}
	
	public void setLinkedNodes( HashMap<Integer, BFNode> linkedNodes )
	{
		this.linkedNodes = linkedNodes;
	}
	
	public IOFSwitch getSwitch() 
	{
		return this.iofSwitch;
	}
	
	public int getDistance()
	{
		return this.distance;
	}
	
	public int getBestPort()
	{
		return this.bestPort;
	}
	
	public HashMap<Integer, BFNode> getLinkedNodes() 
	{
		return this.linkedNodes;
	}
	
	public void addLinkedNode( int port, BFNode node ) 
	{
		this.linkedNodes.put( port, node );
	}
	
	public void removeLinkedNode( int port ) {
		this.linkedNodes.remove( port );
	}
	
}
