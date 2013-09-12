#!/usr/bin/python

from scapy.all import *
interface = 'en1'
probeReqs = []
def sniffProbe(p):
   if p.haslayer(Dot11ProbeReq):
     netName = p.getlayer(Dot11ProbeReq).info
     if netName not in probeReqs:
       probeReqs.append(netName)
       print '[+] Detected New Probe Request: ' + netName
sniff(iface=interface, prn=sniffProbe)



     ##def pktPrint(pkt):
     ## if pkt.haslayer(Dot11Beacon):
     ##sniff(iface="mon0", prn=lambda x: x.summary())
     ##RadioTap / 802.11 Management 8L 00:18:f8:68:c1:bd > ff:ff:ff:ff:ff:ff / Dot11Beacon / SSID='kilozero'


