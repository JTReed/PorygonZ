package edu.wisc.cs.sdn.apps.l3routing;


import net.floodlightcontroller.core.IOFSwitch;

import java.util.Map;
import java.util.HashMap;

public class BFVertex {

	int cost;
	int portOut;
	IOFSwitch iofSwitch;
	
	//holds the outgoing port of immediate neighbors
	Map<Integer, BFVertex> immNeighbors;
	
	public BFVertex(){
		
		this.iofSwitch = null;
		this.cost = -1;
		this.immNeighbors = new HashMap<Integer, BFVertex>();
		
	}
	
	public int getCost() {
		return this.cost;
	
	}
	
	public void setCost(int cost) {
		this.cost = cost;
	
	}
	
	public int getPortOut() {
		return this.portOut;
	
	}
	
	public void setPortOut(int portOut) {
		this.cost = portOut;
	
	} 
	
	public IOFSwitch getSwitch() {
		return this.iofSwitch;

	}
	
	public void setSwitch(IOFSwitch iofSwitch) {
		this.iofSwitch = iofSwitch;
	
	}
	
	public Map<Integer, BFVertex> getImmNeighbors(){
		return immNeighbors;
	
	}
	
	public void addImmNeighbor(int port, BFVertex vertex) {
		immNeighbors.put(port, vertex);
	
	}
	
	
}
