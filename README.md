# wifi_cracker
Learning the basics of 802.11 / messing with Scapy.


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

Every 100ms, an access point sends a broadcast packet containing the following information:

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

- addr1 => DA
- addr2 => SA
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

- find out how to scan nearby AP using beacons
- find connected hosts to the IP by sniffing
- deauth one of the client
- listen to the four-way handshake
- crack the key using dictionnaries and/or bruteforce


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