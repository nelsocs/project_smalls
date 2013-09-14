#!/usr/bin/python

from scapy.all import *
interface = 'mon0'
probeReqs = []

def sniffRadio(p):
   rPkt = p.getlayer(RadioTap)
   version = rPkt.version
   pad = rPkt.pad
   present = rPkt.present
   notdecoded=rPkt.notdecoded
   nPkt = RadioTap(version=version,pad=pad,present=present,notdecoded=notdecoded)
   return nPkt

def sniffProbe(p):
   if p.haslayer(Dot11):
	if p.type == 0 and p.subtype == 8:
		if p.addr2 not in probeReqs:
			probeReqs.append(p.addr2)
			print "AP MAC: %s with SSID: %s " %(p.addr2, p.info) + rPkt.notdecoded
sniffed = sniffRadio and sniffProbe
sniff(iface="mon0", prn = sniffed)
