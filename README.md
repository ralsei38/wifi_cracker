# wifi_cracker
Learning the basics of 802.11 / messing with Scapy.  
**Will probably be ready in a week or two...**
## notes

Here are notes about 802.11  
- first of [theses slides](https://mum.mikrotik.com/presentations/MM19/presentation_7077_1560823308.pdf) are a good starting point.
- [another good starting point](https://howiwifi.com/2020/07/13/802-11-frame-types-and-formats/)

### flow
- the client sends a __probe__ request
- the server sends back a __probe__ response

- the client sends an __authentication__ request
- the server sends an __authentication__ response

- the client sends an __association__ request
- the client sends an __association__ response


### Beacon

Beacons are used by hosts to detect available access points.  
Every 100ms, an access point sends a broadcast packet containing the following information :

- its SSID
- The security protocols it supports (e.g WPA-2)
- The wireless protocols it supports (e.g 802L.11n)

### Directed Probe Request

Instead of relying on passive scanning (aka beacons), a host can sends a "probe" packet, containing the SSID it is looking for.  
If the access point receives the packet, it answers with a probe response.

### Authentication

This stage of the communication is still unencrypted.  
An authentication packet is sent by a host to identify itself.

two types of authentication:

- Open System => No authentication required
- Shared key => (WEP, WPA-2, WPA-3, etc..s.)


The PSK is never sent during communication and must be set manually on The AP and the client.

The client and the AP perform a four-way handshake to generate an encryption key, used for later communications.

During the four-way handshake, the PSK is used to encrypt & decrypt communications.

### note

the piece of code I have in mind will be suited to target mobile hotposts.  
- Brute-force / Dictionary attack could be used to authenticate thus deduce the PSK.
- Brute-force / Dictionary attack could be used on previously saved four-way handshake communications to crack the PSK.



### scapy packets

My first goal is to connect to a mobile hotpost (4 way handshake), in order to get familiar with scapy.

Scapy does not give much details in its documentation concerning 802.11 frames.  
lets dig in [the code](https://github.com/secdev/scapy/blob/master/scapy/layers/dot11.py)

packets must be encapsulated in a `RadioTap` header to send data over the wi-fi
```bash
pkt = RadioTap()
```

you can create a 802.11 frame using the `Dot11` binding
```bash
pkt = RadioTap()/Dot11()
```

Apparently a 802.11 frame contains Information Elements (IE).  
Scapy represent theses parts of frame like so
```bash
class Dot11Elt(Packet):
    """
    A Generic 802.11 Element
    """
    __slots__ = ["info"]
    name = "802.11 Information Element"
    fields_desc = [ByteEnumField("ID", 0, _dot11_id_enum),
                   FieldLenField("len", None, "info", "B"),
                   StrLenField("info", "", length_from=lambda x: x.len,
                               max_length=255)]
```
Somehow [the IPXE documentation](https://dox.ipxe.org/group__ieee80211__ie.html#details) makes it clear.

we could complete our frame like so
```python
pkt = RadioTap()/Dot11()/Dot11Elt()/Dot11Elt()/Dot11Elt() #etc...
```

Now we need to figure out what values can be set in theses Dot11 & Dot11Elt "objects"
we can use `ls()` to see the 802.11 attributes which can be set
```bash
#in a shell
scapy
>>> ls(Dot11)
subtype    : BitMultiEnumField                   = ('0')
type       : BitEnumField                        = ('0')
proto      : BitField  (2 bits)                  = ('0')
cfe        : BitEnumField (Cond)                 = ('0')
FCfield    : MultipleTypeField (FlagsField, FlagsField) = ('<Flag 0 ()>')
ID         : ShortField                          = ('0')
addr1      : _Dot11MacField                      = ("'00:00:00:00:00:00'")
addr2      : _Dot11MacField (Cond)               = ("'00:00:00:00:00:00'")
addr3      : _Dot11MacField (Cond)               = ("'00:00:00:00:00:00'")
SC         : LEShortField (Cond)                 = ('0')
addr4      : _Dot11MacField (Cond)               = ("'00:00:00:00:00:00'")
>>> 
```

types and subtypes can be found [here](https://en.wikipedia.org/wiki/802.11_frame_types)

here we want to establish that four-way handshake, Wikipedia says:
> type:0b0000 	Management 	subtype:0b0100 	=> Probe Request 
```python
pkt = RadioTap()/Dot11(subtype=4, type=0)/Dot11Elt()/Dot11Elt()/Dot11Elt() #etc...
```
also about the Protocol version subfield (`proto` attribute in Scapy)
> The two-bit protocol version subfield is set to 0 for WLAN (PV0) and 1 for IEEE 802.11ah (PV1). 
so we stick to `0`.
```python
pkt = RadioTap()/Dot11(subtype=4, type=0, proto=0)/Dot11Elt()/Dot11Elt()/Dot11Elt() #etc...
```

sadly i don't understand a single thing about the `cfe` attribute

`FCfield` reffers to the Frame control field:
- a schema can be found [on this page](https://dalewifisec.wordpress.com/2014/05/17/the-to-ds-and-from-ds-fields/)
- [a resource](https://networkengineering.stackexchange.com/questions/33041/802-11-how-do-i-find-out-if-packet-is-encrypted-with-wep-or-wpa) to investiguate

from what we read [here](https://mum.mikrotik.com/presentations/MM19/presentation_7077_1560823308.pdf) a probe request contains the SSID and bit rates

I had to dig into Scapy to find the existing IDs... see [here](https://github.com/secdev/scapy/blob/master/scapy/layers/dot11.py#L938) , line 938

```python
#############
# 802.11 IE #
#############

# 802.11-2016 - 9.4.2

_dot11_info_elts_ids = {
    0: "SSID",
    1: "Supported Rates",
    2: "FHset",
    3: "DSSS Set",
    4: "CF Set",
    5: "TIM",
    6: "IBSS Set",
    7: "Country",
    10: "Request",
    11: "BSS Load",
    12: "EDCA Set",
    13: "TSPEC",
    14: "TCLAS",
    15: "Schedule",
    16: "Challenge text",
    32: "Power Constraint",
    33: "Power Capability",
    36: "Supported Channels",
    37: "Channel Switch Announcement",
    42: "ERP",
    45: "HT Capabilities",
    46: "QoS Capability",
    48: "RSN",
    50: "Extended Supported Rates",
    52: "Neighbor Report",
    61: "HT Operation",
    74: "Overlapping BSS Scan Parameters",
    107: "Interworking",
    127: "Extended Capabilities",
    191: "VHT Capabilities",
    192: "VHT Operation",
    221: "Vendor Specific"
}

# Backward compatibility
_dot11_elt_deprecated_names = {
    "Rates": 1,
    "DSset": 3,
    "CFset": 4,
    "IBSSset": 6,
    "challenge": 16,
    "PowerCapability": 33,
    "Channels": 36,
    "ERPinfo": 42,
    "HTinfo": 45,
    "RSNinfo": 48,
    "ESRates": 50,
    "ExtendendCapatibilities": 127,
    "VHTCapabilities": 191,
    "Vendor": 221,
}
```

```python
# self.rates = "\x03\x12\x96\x18\x24\x30\x48\x60"  pasted
pkt = RadioTap()/Dot11(subtype=4, type=0, proto=0)/Dot11Elt(ID="SSID", info="test")/Dot11Elt(ID="Supported Rates", info="???")/Dot11Elt() #etc...
```

Here it is not clear which address is which (client, AP, a 3rd addr ??)
looked up "802.11 field", apparently the order is the following:

- addr1 => DestAddr
- addr2 => SourceAddr
- addr3 => BSS ID (!= SSID, BSSID is an ADDR calculated using the AP's MAC, to uniquely identify the AP)
```bash
addr1      : _Dot11MacField                      = ("'00:00:00:00:00:00'")
addr2      : _Dot11MacField (Cond)               = ("'00:00:00:00:00:00'")
addr3      : _Dot11MacField (Cond)               = ("'00:00:00:00:00:00'")
```



```python
pkt = RadioTap()/Dot11(subtype=4, type=0, proto=0, addr1="DEST-ADDR", addr2="OWN-ADDR", addr3="THE-BSSID")/Dot11Elt(ID="SSID", info="test")/Dot11Elt(ID="Supported Rates", info="???")/Dot11Elt() #etc...
```

- find out how to find the BSSID of an AP, to fill up the `Dot11` frame
- find out how to 4 way handshake own AP
    - try to authenticate to own AP
    - try to associate to own AP
- try to deauthenticate to own AP (will be useful to deauth another user and listen the four-way handshake)

From there we can use beacons (BLACKLIST INSTITUTIONAL AND GOV APs)  
Any way to target mobile hotspot only ?


### code
** note**  
Now we should have what it takes to work on the code.

Here we sniff 20 Beacon frames on our wifi interface
```python
iface="wlp0s20f3"
pkts = sniff(filter="type mgt subtype beacon", iface=iface, count=20)
```

Output
```txt
AP list:
    b'eduroam'
    b'PlanetCampus'
    b'PlanetCampus - Prive 014752'
    b'Redmi Note 11'
```

<!-- Now we need to find a connected user  
we could sniff packets and filter the one having as destination the targeted AP.
From Scapy docstrings
> :param filter:   provide a BPF filter
IBM documentation about BPF [here](https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters) -->

Now we want to connect to an AP.  
[This documentation](https://mrncciew.com/2014/10/10/802-11-mgmt-authentication-frame/) along with theses classes definition where enough to build an authentication packet
```python
# hardocing my MAC address goes brrr
mac_header = Dot11(subtype=11, type=0, proto=0, addr1=target_AP.addr2, addr2="brrr brrr", addr3=target_AP.addr2)
body_frame = Dot11Auth(algo=11, seqnum=1) #wrong algo on purpose, curious about the result
pkt = RadioTap()/mac_header/body_frame
result = srp1(pkt, iface="wlp0s20f3")
```

using `result.show()` here is the result
```bash
###[ 802.11-FCS ]### 
     subtype   = Authentication
     type      = Management
     proto     = 0
     FCfield   = 
     ID        = 14849
     addr1     = brrr brrr (RA=DA)
     addr2     = heh (TA=SA)
     addr3     = heh (BSSID/STA)
     SC        = 48928
     fcs       = 0xc5c2ab34
###[ 802.11 Authentication ]### 
        algo      = 11
        seqnum    = 2
        status    = algo-unsupported
```

algo unsported, which makes sense:

- 0 is meant to authentication without any added security layer
- 1 is meant to authenticate using a Pre-Shared Key secured (WPAx)

using `algo=0` returns the following even tho my mobile hotspot is configured to use WPA2 ?!!
```txt
##[ 802.11 Authentication ]### 
        algo      = open
        seqnum    = 2
        status    = success
```

lets try to authenticate for real this time, we'll see later about that Open System authentication
```python
# AUTHENTICATION PHASE-------
# https://mrncciew.com/2014/10/10/802-11-mgmt-authentication-frame/
# not using Ether().src, it uses my ethernet mac... to lazy to search
mac_header = Dot11(subtype=11, type=0, proto=0, addr1=target_AP.addr2, addr2=own_MAC, addr3=target_AP.addr2)
body_frame = Dot11Auth(algo=1, seqnum=1)
pkt = RadioTap()/mac_header/body_frame
print("AUTHENTICATION PHASE !!!")
result = srp1(pkt, iface="wlp0s20f3")
result.show()
# AUTHENTICATION PHASE-------
```

which returns
```text
Begin emission:
Finished sending 1 packets.
.......................................*
Received 40 packets, got 1 answers, remaining 0 packets
###[ RadioTap ]### 
blabla...
###[ 802.11-FCS ]### 
     subtype   = Authentication
     type      = Management
     proto     = 0
     FCfield   = 
     ID        = 14849
     addr1     = heh (RA=DA)
     addr2     = heh(TA=SA)
     addr3     = heh (BSSID/STA)
     SC        = 37568
     fcs       = 0x296dc947
###[ 802.11 Authentication ]### 
        algo      = sharedkey
        seqnum    = 2
        status    = success
###[ 802.11 Information Element ]### 
           ID        = Challenge text
           len       = 128
           info      = "\x1f\\xdcD'J%\\xc5\\xd4U\x14N!d\\xcdΓ\\x91\\xb0\x17?ɶ\\xe2dw^\\xf2\\xc7\\xc4\\xdfG\\x82$/\\xf9\\xc0*ڕ6\\xaa\\x97\\xd1dsZ\\x8d\x0fz\\xb3C7Q\\xab\\x80B\\xd2\x1f\\xfdU\\xfeo\\xf5D\x7f\\xb4\\I\\xd8\x14\x1d\\x96&?(\x1d\x1d\x16L\\xf2j.e\\x91\\xf2\\x84\\x86\x00\\xb4\\xb0\\x9e*\\xb3Q3@\\xc8\x11\\xaeR\\xedܷ\x15\\x892\\xf6P:\\xfa\\x9em\\xaa\\x8d\\x88\\xd7bA5\\xd4q\\xc9\\xcf\n\\xc7\\xeez`"
```

we received a challenge, I have no idea how the authentication process works, after some research I realized that this is the tricky part...  
Many concepts are discussed here so that i can keep working without being overwhelmed.

---

### 4-Way Handshake

i'd like to focus on the standard but everything is poorly managed and not welcoming.
Finding / Reading an RFC is pretty straight forward, but i could not find good official documentation about wifi authentication.

sources:
- EEE 802.11i [here](https://fr.wikipedia.org/wiki/IEEE_802.11i)
- [802.11i Overview (2005)](https://ieee802.org/16/liaison/docs/80211-05_0123r1.pdf)
- [introduction-to-wpa-key-hierarchy](https://networklessons.com/cisco/ccnp-encor-350-401/introduction-to-wpa-key-hierarchy)
- [EAPol](https://networklessons.com/cisco/ccnp-encor-350-401/eapol-extensible-authentication-protocol-over-lan)
- https://www.wifi-professionals.com/2019/01/4-way-handshake

802.11i security norm which define 3 types of authentication mechanism:
- authentication using 802.1X and EOP (port based authentication)
- Authentication using the AES algorithm

**In both cases the transport protocol in use is EAP (Extensible Authentication Protocol)**

Once authenticated both the client and the access point know the **Pairwise Master Key** (description below).

From there, a **4-way handhsake** happens between a client (supplicant) and an AP (authenticator).
To generate a Private Transient Key, and encrypt communications using it.

?The PMK is a temporary key?  
!it is not used to encrypt coms !

```
PTK = PRF (PMK + Anonce + SNonce + Mac (AA)+ Mac (SA))
```
- `Anonce`  a random number generated by the Authenticator
- `Snonce`  a random number generated by the Supplicant
- `MAC(SA)` mac address of the supplicant
- `MAC(AA)` mac address of the authenticator
- `PRF()` is a pseudo-random function which is applied to the whole
- `MSK` the PSK is the first generated key when authenticating using PSK or 802.1X/EAP
- `PMK` the PSK key is generated from the MSK key
- `PTK` the PTK is the key used for encrpytion, it is generated using the PMK

for multicast encryption, MSK -> GMK -> GTK is generate, kind of the same flow as for MSK ->  PMK ->  PTK

---

- [this documentation](https://www.wifi-professionals.com/2019/01/4-way-handshake) seems straight-forward
### Robust Security Network Authentication (RSNA)
> some documentation [see here](https://techhub.hpe.com/eginfolib/networking/docs/routers/msrv7/cg/5200-3028_wlan_cg/content/466576912.htm)
>  The initial authentication process is carried out either using a pre-shared key (PSK), or following an EAP exchange through 802.1X [doc](https://en.wikipedia.org/wiki/IEEE_802.11i-2004)
> when using PSK, fist few packets are encrypted using it, then a Pairwise Master key is generated (derivated from the PSK) and used from there to encrypt content. Once the 4 way handshake occured, a Private Transiant Key is generated, and use to encrypt communications.
- authentication standard for WLAN is called 802.1X
- [Extensible Authentication Protocol (EAP)](https://www.ietf.org/rfc/rfc3748.txt)
- Scapy supports eap [see eap.py](https://github.com/secdev/scapy/blob/master/scapy/layers/eap.py)
- eap packet format [here](https://techhub.hpe.com/eginfolib/networking/docs/switches/5130ei/5200-3946_security_cg/content/485048061.htm)

---

## EAP

[This video](https://youtu.be/bzWdE0Hc-jQ) is a good starting point.
Here is a recap:

- EAP is a transport protocol used to authenticate users over WLAN or LAN networks.
- EAP is media-independent, it operates at the layer 2
- EAP supports a variety of authentication protocols
- before being authenticate, any packets relying on another transport protocol such as TCP will be dropped.

**EAP only concerns WPA/WPA2-Enterprise which is more sophisticated != WPA/WPA2-PSK !!!**

rip, back to the start
this may be of interest: https://cisco.goffinet.org/ccna/wlan/protocoles-securite-sans-fil-wpa-wpa2-wpa3:
- table states that: WPA2 personnal + PSK  => TKIP security, itself using RC4 algorithm and rotates key regularly.
- section 8. Four-Way Handshake

seems a bit too much of a headache to work on an authentication using scapy for now...
authentication itself seems harder than getting into an AP by attacking it...

lets focus on deauth and dictionnary / bruteforce attack for now.
If I'm still motivated after this, i'll work on the 4 way handshake =)
---


using the `haslayer()` `getlayer()` we can check for the challenge text existence
```python

#############
# 802.11 IE #
#############

# 802.11-2016 - 9.4.2

_dot11_info_elts_ids = {
    0: "SSID",
    1: "Supported Rates",
    2: "FHset",
    3: "DSSS Set",
    4: "CF Set",
    5: "TIM",
    6: "IBSS Set",
    7: "Country",
    10: "Request",
    11: "BSS Load",
    12: "EDCA Set",
    13: "TSPEC",
    14: "TCLAS",
    15: "Schedule",
    16: "Challenge text",
    #etc...
}
```

```python
```

```python
_dot11_info_elts_ids = {
    0: "SSID",
    1: "Supported Rates",
    2: "FHset",
    3: "DSSS Set",
    4: "CF Set",
    5: "TIM",
    6: "IBSS Set",
    7: "Country",
    10: "Request",
    11: "BSS Load",
    12: "EDCA Set",
    13: "TSPEC",
    14: "TCLAS",
    15: "Schedule",
    16: "Challenge text",
    32: "Power Constraint",
    33: "Power Capability",
    36: "Supported Channels",
    37: "Channel Switch Announcement",
    42: "ERP",
    45: "HT Capabilities",
    46: "QoS Capability",
    48: "RSN",
    50: "Extended Supported Rates",
    52: "Neighbor Report",
    61: "HT Operation",
    74: "Overlapping BSS Scan Parameters",
    107: "Interworking",
    127: "Extended Capabilities",
    191: "VHT Capabilities",
    192: "VHT Operation",
    221: "Vendor Specific"
}
```
---


!!! warning
    Sometimes mobile hotspot are not detected,
    somehow turning off then back on the interface fixes it...


- [ ] find connected hosts to the IP by sniffing
- [ ] deauth one of the client
- [ ] listen to the four-way handshake
- [ ] crack the key using dictionnaries and/or bruteforce

---

this can be useful in scapy interpreter
```text
scapy
>>> explore()
>>> ls(className)
>>> ls(Dot11)
>>> ls(Dot11Elt)
>>> ...
```

The main problem is that shared access point are used with weak passwords, simply because sharing a 123 character long string to someone for them to connect to your SAP is far from practical...

A solution could be to use a simple QR code application that contains your strong PSK.

This way the user (client) can scan it, copy the key and paste it in their configuration.

### note
- promiscuous mode must be enabled on the WNIC, to sniff packets without having to associate with an AP.
- monitor mode allows to sniff packets but you need to be connected to the AP !
- managed mode, no sniffing.

see the script to switch back & to monitor mode.

## TO DO
- [x] use beacon to enumerate nearby APs
- [x] authenticate to my own 4g mobile hotspot using Open System authenticate (find out why this returns a success code, even tho i set WPA2 on my hotspot)
- [ ] authenticate to my own 4g mobile hotspot using WPA2 and a PSK (no bruteforce, as a regular user)
- [ ] associate to my own 4g mobile hotspot using WPA2 and a PSK (no bruteforce, as a regular user)
- [ ] what can we do from there ?
