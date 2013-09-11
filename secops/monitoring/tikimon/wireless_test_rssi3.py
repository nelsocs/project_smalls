import sys
from scapy.all import *

interface='mon0'
conf.iface=interface
wlist=list()
def sniffAP(p):
	global wlist
     if ( (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp))
				and not ap.has key(p(Dot11).addr3)):
	   ssid		= p[Dot11Elt].info
	   bssid	= p[Dot11].addr3
	   power	= p.sprintf("(PrismHeader:%PrismHeader.signal%)")
	
