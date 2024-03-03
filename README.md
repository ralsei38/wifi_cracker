# wifi_cracker
Learning the basics of 802.11 / messing with Scapy.


## notes

Here are notes about 802.11  
first of [this link](https://mum.mikrotik.com/presentations/MM19/presentation_7077_1560823308.pdf) seems like a good starting point.

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

Instead of relying on passive scanning (aka beacons), a host can sends a "probe" packet, containing the SSID it is looking for. If the access point receives the packet, it answers with a probe response.

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
```text
>>> explore()
>>> explore()
Packets contained in scapy.layers.dot11:
Class                           |Name                                
--------------------------------|------------------------------------
AKMSuite                        |AKM suite                           
Dot11                           |802.11                              
Dot11ATIM                       |802.11 ATIM                         
Dot11Ack                        |802.11 Ack packet                   
Dot11AssoReq                    |802.11 Association Request          
Dot11AssoResp                   |802.11 Association Response         
Dot11Auth                       |802.11 Authentication               
Dot11Beacon                     |802.11 Beacon                       
Dot11CCMP                       |802.11 CCMP packet                  
Dot11Deauth                     |802.11 Deauthentication             
Dot11Disas                      |802.11 Disassociation               
Dot11Elt                        |802.11 Information Element          
Dot11EltCountry                 |802.11 Country                      
Dot11EltCountryConstraintTriplet|802.11 Country Constraint Triplet   
Dot11EltDSSSet                  |802.11 DSSS Parameter Set           
Dot11EltERP                     |802.11 ERP                          
Dot11EltHTCapabilities          |802.11 HT Capabilities              
Dot11EltMicrosoftWPA            |802.11 Microsoft WPA                
Dot11EltRSN                     |802.11 RSN information              
Dot11EltRates                   |802.11 Rates                        
Dot11EltVendorSpecific          |802.11 Vendor Specific              
Dot11Encrypted                  |802.11 Encrypted (unknown algorithm)
Dot11FCS                        |802.11-FCS                          
Dot11ProbeReq                   |802.11 Probe Request                
Dot11ProbeResp                  |802.11 Probe Response               
Dot11QoS                        |802.11 QoS                          
Dot11ReassoReq                  |802.11 Reassociation Request        
Dot11ReassoResp                 |802.11 Reassociation Response       
Dot11TKIP                       |802.11 TKIP packet                  
Dot11WEP                        |802.11 WEP packet                   
PMKIDListPacket                 |PMKIDs                              
PrismHeader                     |Prism header                        
RSNCipherSuite                  |Cipher suite                        
RadioTap                        |RadioTap                            
RadioTapExtendedPresenceMask    |RadioTap Extended presence mask     
RadioTapTLV                     |                                    
>>> explore()
Packets contained in scapy.layers.dot15d4:
Class                     |Name                                        
--------------------------|--------------------------------------------
Dot15d4                   |802.15.4                                    
Dot15d4Ack                |802.15.4 Ack                                
Dot15d4AuxSecurityHeader  |802.15.4 Auxiliary Security Header          
Dot15d4Beacon             |802.15.4 Beacon                             
Dot15d4Cmd                |802.15.4 Command                            
Dot15d4CmdAssocReq        |802.15.4 Association Request Payload        
Dot15d4CmdAssocResp       |802.15.4 Association Response Payload       
Dot15d4CmdCoordRealign    |802.15.4 Coordinator Realign Command        
Dot15d4CmdCoordRealignPage|802.15.4 Coordinator Realign Page           
Dot15d4CmdDisassociation  |802.15.4 Disassociation Notification Payload
Dot15d4CmdGTSReq          |802.15.4 GTS request command                
Dot15d4Data               |802.15.4 Data                               
Dot15d4FCS                |802.15.4 - FCS                              
>>> 
```