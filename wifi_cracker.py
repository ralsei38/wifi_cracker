from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq, RadioTap, sendp, srp1, sr, sniff, Ether, EAP
from scapy.all import AsyncSniffer
from scapy.layers.eap import EAPOL
import sys
import pdb


AP_MAC = "ff:ee:ff:ff:ff:ff"
own_MAC = "e0:2e:0b:98:d2:2b"
BSSID = "" #empty to default on real one

# listen for Beacon frames
def list_AP() -> list:
    """
    returns a list of nearby APs
    """
    pkts = sniff(filter="type mgt subtype beacon", iface="wlp0s20f3", count=50)
    APs = []
    for pkt in pkts:
        if pkt.info not in [AP.info for AP in APs]:
            APs.append(pkt)

    return APs

APs = list_AP()
for AP in APs:
    print(AP.info)
target_AP = input("AP:") # "ggg" being my mobile hotspot
if target_AP.encode() not in [ AP.info for AP in APs]:
    print("This AP cannot be targeted...")
    print("exiting")
    sys.exit()
for AP in APs:
    if AP.info == target_AP.encode():
        target_AP = AP
        print("AP is available, start of auth phase")
        break
if target_AP == "":
    print("target IP not found...")
    sys.exit()

# AUTHENTICATION PHASE-------
# not using Ether().src, it uses my ethernet mac... to lazy to search
# I have to first authenticate and associate. After successful association, AP finally sends an EAP Request Identity packet.
mac_header = Dot11(subtype=11, type=0, proto=0, addr1=target_AP.addr2, addr2=own_MAC, addr3=target_AP.addr2)
body_frame = Dot11Auth(algo=0, seqnum=1) #Open System authentication, then use EAP to identify later on...
pkt = RadioTap()/mac_header/body_frame
print("AUTHENTICATION PHASE !!!")
result = srp1(pkt, iface="wlp0s20f3")
# result.show()
if result.haslayer(Dot11Auth) and result.getlayer(Dot11Auth).status == 0:
    print("Open system authentication: Success")
else:
    print("Open system authentication: Failure")
    print("wrong status code ?")
    print("exiting...")
    sys.exit()
# AUTHENTICATION PHASE-------

# ASSOCIATION PHASE-------
print("ASSOCIATION PHASE !!!")
async_sniffer = AsyncSniffer(
    lfilter=lambda pkt: pkt.haslayer(EAPOL),
    iface="wlp0s20f3",
    count=1
)
async_sniffer.start()
mac_header = Dot11(subtype=0, type=0, proto=0, addr1=target_AP.addr2, addr2=own_MAC, addr3=target_AP.addr2)
body_frame = Dot11AssoReq()
pkt = RadioTap()/mac_header/body_frame
result = srp1(pkt, iface="wlp0s20f3")
result.show()
# ASSOCIATION PHASE-------

# EAP PHASE-------------
# counts => each packet or only the one filtered ? (sniffing post to the association phase may be safer)

print("4 WAY HANDSHAKE !!!")
async_sniffer.join()
# EAP PHASE-------------






# idk idc phase
# dot11_frame = Dot11(subtype=11, type=0, proto=0, addr1='ff:ff:ff:ff:ff:ff',
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
