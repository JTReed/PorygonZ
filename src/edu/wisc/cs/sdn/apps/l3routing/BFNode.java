package edu.wisc.cs.sdn.apps.l3routing;

import java.util.Map;
import java.util.HashMap;
import net.floodlightcontroller.core.IOFSwitch;

public class BFNode {
	private IOFSwitch iofSwitch;
	private int distance;
	private BFNode previousNode;
	private HashMap<Integer, BFNode> linkedNodes;
	
	public BFNode() 
	{
		this.iofSwitch = null;
		this.distance = 0;
		this.previousNode = null;
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
	
	public void setPreviousNode( BFNode node )
	{
		this.previousNode = node;
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
	
	public BFNode getPreviousNode()
	{
		return this.previousNode;
	}
	
	public HashMap<Integer, BFNode> getLinkedNodes() 
	{
		return this.linkedNodes;
	}
	
}
