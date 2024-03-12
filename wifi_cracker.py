from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq, RadioTap, sendp, srp1, sr, sniff, Ether, EAP
import pdb


AP_MAC = "ff:ee:ff:ff:ff:ff"
own_MAC = "ff:ee:ff:ff:ff:ff"
BSSID = "" #empty to default on real one

# listen for Beacon frames
def list_AP() -> list:
    """
    returns a list of nearby APs
    """
    pkts = sniff(filter="type mgt subtype beacon", iface="wlp0s20f3", count=20)
    APs = []
    for pkt in pkts:
        if pkt.info not in [AP.info for AP in APs]:
            APs.append(pkt)

    return APs

APs = list_AP()
target_AP = "" # "ggg" being my mobile hotspot 
for AP in APs:
    if AP.info == "ggg".encode():
        target_AP = AP
        break
if target_AP =="":
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
result.show()
if result.haslayer(Dot11Elt) and code = result.getlayer(Dot11Elt).status == 0:
    print("Open system authentication: Success")
else:
    print("Open system authentication: Failure")
    print("wrong status code ?")
    print("exiting...")
    sys.exit()
# AUTHENTICATION PHASE-------



# ASSOCIATION PHASE-------
print("ASSOCIATION PHASE !!!")
mac_header = Dot11(subtype=0, type=0, proto=0, addr1=target_AP.addr2, addr2=own_MAC, addr3=target_AP.addr2)
body_frame = Dot11AssoReq()
pkt = RadioTap()/mac_header/body_frame
result = srp1(pkt, iface="wlp0s20f3")
result.show()
# ASSOCIATION PHASE-------



# EAP PHASE-------------
# counts => each packet or only the one filtered ? (sniffing post to the association phase may be safer)
eap_1 = sniffer(interface="wlp0s20p3", lfilter= lambda pkt:pkt if pkt.haslayer(EAP), count=1) 
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
