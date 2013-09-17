#!/usr/bin/python

from scapy.all import *
interface = 'mon0'
probeReqs = []
def sniffProbe(p):
   if p.haslayer(Dot11ProbeReq):
     netName = p.getlayer(Dot11ProbeReq).info
     rPkt = p.getlayer(RadioTap)
     power_src = -(256-ord(p.notdecoded[-4:-3]))
     power_src_str = str(power_src)

     if netName not in probeReqs:
       probeReqs.append(netName)
       print '[+] Detected New Probe Request: ' + netName + ' signal: '  + power_src_str


     ##if netName in probeReqs:
     if netName in probeReqs and not [None] :
       print '[+] Detected Additional Probe Request: ' + netName + ' signal: ' + power_src_str
sniff(iface=interface, prn=lambda x:sniffProbe(x))
