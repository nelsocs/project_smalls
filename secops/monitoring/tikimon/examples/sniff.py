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
from scapy import *

def sniff_beacon(p):
        # check to see if it is an 802.11 frame
            if not p.haslayer(Dot11):
                        return

                        # now check if it is has a beacon layer
                            if not p.haslayer(Dot11Beacon):
                                        return

                                        print p.display

                                        sniff(iface="ath0", prn=sniff_beacon)
