from scapy.all import sniff
# PROBING PHASE-------
# listen for Beacon frames
def probing(iface: str):
    print("PROBING PHASE")
    pkts = sniff(filter="type mgt subtype beacon", iface=iface, count=50)
    APs = []
    for pkt in pkts:
        if pkt.info not in [AP.info for AP in APs]:
            APs.append(pkt)

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
            break
    if target_AP == "":
        print("target IP not found...")
        sys.exit()
    return AP
# PROBING PHASE-------