from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump, sr, sniff
import pdb
AP_MAC = "ff:ee:ff:ff:ff:ff"
client_MAC = "" #empty to default on real one
BSSID = "" #empty to default on real one

# listen for Beacon frames
pkts = sniff(filter="type mgt subtype beacon", iface="wlp0s20f3", count=2)
# SSIDS = 
#based on SSIds see white / blaclist and try deauth attack one by one
# dot11_frame = Dot11(subtype=8, type=0, proto=0, addr1='ff:ff:ff:ff:ff:ff',
# addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
# beacon_frame = Dot11Beacon()
# pkt = RadioTap()/dot11_frame/beacon_frame
# pkt.show()
# ans,unans = sr(pkt)
# pdb.set_trace()
# pkt = RadioTap()\
#     /Dot11(subtype=4, type=0, proto=0, addr1="DEST-ADDR", addr2="OWN-ADDR", addr3="THE-BSSID")\
#     /Dot11Elt(ID="SSID", info="test")\
#     /Dot11Elt(ID="Supported Rates", info="???")\
#     /Dot11Elt() #etc...