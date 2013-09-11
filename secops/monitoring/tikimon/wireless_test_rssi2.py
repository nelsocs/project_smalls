#!/usr/bin/python

from scapy.all import *
interface = 'mon0'
probeReqs = []
def sniffProbe(p):
   if p.haslayer(Dot11):
	if p.type == 0 and p.subtype == 8:
		if p.addr2 not in probeReqs:
			probeReqs.append(p.addr2)
			print "AP MAC: %s with SSID: %s " %(p.addr2, p.info)
sniff(iface="mon0", prn = sniffProbe) 
