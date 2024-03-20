from scapy.all import Dot11, Dot11AssoReq, Dot11Beacon, Dot11Elt, Dot11EltRates, Dot11EltRSN, AKMSuite, RSNCipherSuite, RadioTap, srp1
import pdb
# ASSOCIATION PHASE-------
def get_elt(pkt, ID) -> Dot11Elt:
    """Returns the information element for a given ID"""
    layer = pkt.getlayer(Dot11Elt)
    while layer is not None and layer.ID != ID:
        layer = layer.getlayer(Dot11Elt, 2)
    return layer

def association(own_MAC, AP_beacon, iface):
    AP_mac = AP_beacon.addr2
    cap = AP_beacon.cap
    rates = AP_beacon.getlayer(Dot11EltRates).rates
    ssid = AP_beacon.info.decode()
    print("ASSOCIATION PHASE !!!")
    dot11_header = Dot11(subtype=0, type=0, addr1=AP_mac, addr2=own_MAC, addr3=AP_mac)
    dott11_element_assoreq = Dot11AssoReq(cap=cap, listen_interval=20)
    dott11_element_ssid = Dot11Elt(ID=0, info=ssid, len=len(ssid))
    dott11_element_ssid = Dot11EltRates(ID=1, rates=rates, len=len(rates))
    es_rates = get_elt(AP_beacon, 50)
    if es_rates is not None:
        es_rates = Dot11Elt(
            ID=50,
            info=es_rates.info,
            len=len(es_rates.info)
        )
    pkt = RadioTap() / dot11_header / dott11_element_assoreq / dott11_element_ssid
    if es_rates is not None:
        pkt /= es_rates
    
    dott11_element_RSN = Dot11EltRSN(    
        ID=48,    
        len=20,    
        version=1,
        group_cipher_suite=RSNCipherSuite(cipher='CCMP-128'),    
        nb_pairwise_cipher_suites=1,    
        pairwise_cipher_suites=RSNCipherSuite(cipher='CCMP-128'),    
        nb_akm_suites=1,    
        akm_suites=AKMSuite(suite='PSK'))
    pkt /= dott11_element_RSN
    result = srp1(pkt, iface=iface)
    pdb.set_trace()
# ASSOCIATION PHASE-------