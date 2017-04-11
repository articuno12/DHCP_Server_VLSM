def DhcpDiscover(MacAddress) :
    OP = b'\x01'     #Message type: Boot Request (1)
    HTYPE = b'\x01'  #Hardware type: Ethernet
    HLEN = b'\x06'   #Hardware address length: 6
    HOPS = b'\x00'   #Hops: 0
    XID = b'\x39\x03\xF3\x26'   #Transaction ID
    SECS = b'\x00\x00'   	    #Seconds elapsed: 0
    FLAGS = b'\x80\x00'	    #Bootp flags: 0x8000 (Broadcast) + reserved flags
    CIADDR = b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    YIADDR = b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
    SIADDR = b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
    GIADDR = b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    CHADDR1 = MacAddress
    CHADDR2 = b'\x00\x00'
    CHADDR3 = b'\x00\x00\x00\x00'
    CHADDR4 = b'\x00\x00\x00\x00'
    CHADDR5 = bytes(192)           		   #Client hardware address padding: 00000000000000000000
    MagicCookie = b'\x63\x82\x53\x63'  	   #Magic cookie: DHCP
    DHCPOptions1 = b'\x35\x01\x01' 	    	   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
    End = b'\xff'    #End Option

    package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + MagicCookie + DHCPOptions1 + End
    return package


def DhcpOffer(ClientMacAddress,TransactionId,ServerIp,OfferedIp,SubnetMask) :
    OP = bytes([0x02])
    HTYPE = bytes([0x01])
    HLEN = bytes([0x06])
    HOPS = bytes([0x00])
    XID = TransactionId
    SECS = bytes([0x00, 0x00])
    FLAGS = bytes([0x00, 0x00])
    CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
    YIADDR = bytes(OfferedIp)
    SIADDR = bytes(ServerIp)
    GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
    CHADDR1 = ClientMacAddress
    CHADDR2 = bytes([0x00, 0x00])
    CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
    CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
    CHADDR5 = bytes(192)
    Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1 = bytes([53 , 1 , 2]) # DHCP Offer
    DHCPOptions2 = bytes([1 , 4 , SubnetMask[0], SubnetMask[1], SubnetMask[2], SubnetMask[3] ]) # SubnetMask
    DHCPOptions3 = bytes([3 , 4 , ServerIp[0], ServerIp[1], ServerIp[2], ServerIp[3] ]) #192.168.1.1 router
    DHCPOptions4 = bytes([51 , 4 , 0x00, 0x01, 0x51, 0x80]) #86400s(1 day) IP address lease time
    DHCPOptions3 = bytes([3 , 4 , ServerIp[0], ServerIp[1], ServerIp[2], ServerIp[3] ]) # DHCP Server
    End = bytes([0xff])

    package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5 + End

    return package

def DhcpRequest(MacAddress,TransactionId,ServerIp,RequestedIp):
    OP = b'\x01'     #Message type: Boot Request (1)
    HTYPE = b'\x01'  #Hardware type: Ethernet
    HLEN = b'\x06'   #Hardware address length: 6
    HOPS = b'\x00'   #Hops: 0
    XID = TransactionId   #Transaction ID
    SECS = b'\x00\x00'   	    #Seconds elapsed: 0
    FLAGS = b'\x80\x00'	    #Bootp flags: 0x8000 (Broadcast) + reserved flags
    CIADDR = b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    YIADDR = b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
    SIADDR = bytes(ServerIp)   #Next server IP address: 0.0.0.0
    GIADDR = b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    CHADDR1 = MacAddress
    CHADDR2 = b'\x00\x00'
    CHADDR3 = b'\x00\x00\x00\x00'
    CHADDR4 = b'\x00\x00\x00\x00'
    CHADDR5 = bytes(192)               	     #Client hardware address padding: 00000000000000000000
    MagicCookie = b'\x63\x82\x53\x63'  	     #Magic cookie: DHCP
    DHCPOptions1 = bytes([53 , 1 , 3])     	     #Option: (t=53,l=1) DHCP Message Type = DHCP Request
    DHCPOptions2 = bytes([50 , 4 , RequestedIp[0], RequestedIp[1], RequestedIp[2], RequestedIp[3]])   #Option: (t=50,l=4) Requested IP Adress
    DHCPOptions3 = bytes([54 , 4 , ServerIp[0], ServerIp[1], ServerIp[2], ServerIp[3]])   #Option: (t=54,l=4) DHCP Server Identifier
    End = b'\xff'   #End option

    package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + MagicCookie + DHCPOptions1 + DHCPOptions2 +  DHCPOptions3 + End

    return package
