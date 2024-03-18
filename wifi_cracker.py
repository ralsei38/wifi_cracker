from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq, RadioTap, sendp, srp1, sr, sniff, Ether, EAP
from scapy.all import AsyncSniffer
from scapy.layers.eap import EAPOL
import sys
import pdb
import probing, association, authentication, handshake

AP_MAC = "ff:ee:ff:ff:ff:ff"
own_MAC = ""
BSSID = "" #empty to default on real one
IFACE="wlp0s20f3"
AP_beacon = probing.probing(iface=IFACE)
authentication.authentication(own_MAC=own_MAC, AP_beacon=AP_beacon, iface=IFACE)
association.association(own_MAC=own_MAC, AP_beacon=AP_beacon, iface=IFACE)