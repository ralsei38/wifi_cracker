# EAP PHASE-------------
# Voir documentation 5.6.3 second part, EAPol start FROM THE CLIENT
# see class class WPA_key(Packet): which should be name EAPOL_KEY but here we are...
def handshake():
    pkt = RadioTap()/Dot11()/Eap()
# counts => each packet or only the one filtered ? (sniffing post to the association phase may be safer)

print("4 WAY HANDSHAKE !!!")
# EAP PHASE-------------

#https://www.google.com/url?sa=i&url=https%3A%2F%2Fcommunity.nxp.com%2Ft5%2FWireless-Connectivity-Knowledge%2F802-11-Wi-Fi-Security-Concepts%2Fta-p%2F1163551&psig=AOvVaw1vTFE57ud7eTSOjyO3Skp8&ust=1710873910476000&source=images&cd=vfe&opi=89978449&ved=0CBMQjRxqFwoTCKDW_8PJ_oQDFQAAAAAdAAAAABAD