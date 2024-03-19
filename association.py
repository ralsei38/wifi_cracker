from scapy.all import Dot11, Dot11AssoReq, Dot11Beacon, Dot11Elt, Dot11EltRates, Dot11EltRSN, AKMSuite, RSNCipherSuite, RadioTap, srp1
import pdb
# ASSOCIATION PHASE-------
def association(own_MAC, AP_beacon, iface):
    AP_mac = AP_beacon.addr2
    cap = AP_beacon.cap
    rates = AP_beacon.rates
    ssid = AP_beacon.info.decode()
    print("ASSOCIATION PHASE !!!")
    dot11_header = Dot11(subtype=0, type=0, proto=0, addr1=AP_mac, addr2=own_MAC, addr3=AP_mac)
    dott11_element_assoreq = Dot11AssoReq(cap=cap, listen_interval=20)
    dott11_element_ssid = Dot11Elt(ID=0, info=ssid, len=len(ssid))
    dott11_element_RSN = Dot11EltRSN(    
        ID=48,    
        len=20,    
        version=1,    
        group_cipher_suite=RSNCipherSuite(cipher='CCMP-128'),    
        nb_pairwise_cipher_suites=1,    
        pairwise_cipher_suites=RSNCipherSuite(cipher='CCMP-128'),    
        nb_akm_suites=1,    
        akm_suites=AKMSuite(suite='PSK'))
    pkt = RadioTap()/dot11_header/dott11_element_assoreq/dott11_element_ssid/dott11_element_RSN
    result = srp1(pkt, iface=iface)
# ASSOCIATION PHASE-------
