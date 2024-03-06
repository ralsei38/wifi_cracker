from scapy.all import Dot11,Dot11Beacon,Dot11Elt,Dot11Auth,Dot11AssoReq,RadioTap,sendp, srp1, sr, sniff, Ether
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
    exit

# authentication phase https://mrncciew.com/2014/10/10/802-11-mgmt-authentication-frame/
# not using Ether().src, it uses my ethernet mac... to lazy to search
mac_header = Dot11(subtype=11, type=0, proto=0, addr1=target_AP.addr2, addr2=own_MAC, addr3=target_AP.addr2)
body_frame = Dot11Auth(algo=0, seqnum=1)
pkt = RadioTap()/mac_header/body_frame
result = srp1(pkt, iface="wlp0s20f3")
result.show()


# association phase
mac_header = Dot11(subtype=0, type=0, proto=0, addr1=target_AP.addr2, addr2=own_MAC, addr3=target_AP.addr2)
body_frame = Dot11AssoReq()
pkt = RadioTap()/mac_header/body_frame
result = srp1(pkt, iface="wlp0s20f3")
result.show()

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