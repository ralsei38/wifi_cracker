from scapy.all import Dot11, Dot11Auth, RadioTap, srp1
# AUTHENTICATION PHASE-------
# not using Ether().src, it uses my ethernet mac... to lazy to search
# I have to first authenticate and associate. After successful association, AP finally sends an EAP Request Identity packet.
def authentication(own_MAC: str, AP_beacon: str, iface: str):
    mac_header = Dot11(subtype=11, type=0, proto=0, addr1=AP_beacon.addr2, addr2=own_MAC, addr3=AP_beacon.addr2)
    body_frame = Dot11Auth(algo=0, seqnum=1, status='success') #Open System authentication, then use EAP to identify later on...
    pkt = RadioTap()/mac_header/body_frame
    print("AUTHENTICATION PHASE !!!")
    result = srp1(pkt, iface=iface, inter=2)
    # result.show()
    if result.haslayer(Dot11Auth) and result.getlayer(Dot11Auth).status == 0:
        print("Open system authentication: Success")
    else:
        print("Open system authentication: Failure")
        print("wrong status code ?")
        print("exiting...")
        sys.exit()
# AUTHENTICATION PHASE-------

