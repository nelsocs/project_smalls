#!/usr/bin/python

from scapy.all import *
interface = 'mon0'
probeReqs = []
def sniffProbe(p):
   if p.haslayer(Dot11ProbeReq):
     netName = p.getlayer(Dot11ProbeReq).info
     #power = p.sprintf("(PrismHeader:%PrismHeader.signal%)")
     rPkt = p.getlayer(RadioTap)
     power_src = -(256-ord(p.notdecoded[-4:-3]))
     ##power_src = rPkt.notdecoded

     if netName not in probeReqs:
       probeReqs.append(netName)
       print '[+] Detected New Probe Request: ' + netName + power_src
sniff(iface=interface, prn=lambda x:sniffProbe(x))
##sniff(iface=interface, prn=sniffProbe)



     ##def pktPrint(pkt):
     ## if pkt.haslayer(Dot11Beacon):
     ##sniff(iface="mon0", prn=lambda x: x.summary())
     ##RadioTap / 802.11 Management 8L 00:18:f8:68:c1:bd > ff:ff:ff:ff:ff:ff / Dot11Beacon / SSID='kilozero'

#def sniffRadio(p):
   #rPkt = p.getlayer(RadioTap)
   #version = rPkt.version
   #pad = rPkt.pad
   #present = rPkt.present
   #notdecoded=rPkt.notdecoded
   #nPkt = RadioTap(version=version,pad=pad,present=present,notdecoded=notdecoded)
   #return nPkt
