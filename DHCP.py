def hex2bytestring(hexstring) :
    bytestring = b''
    for i in range(len(hexstring)) :
        if isinstance(hexstring[i],str) :
            print(hexstring[i])
            bytestring = bytestring + struct.pack('!B',int(hexstring[i],16))
        else :
            bytestring = bytestring + struct.pack('!B',int(hexstring[i]))
    return bytestring

def bytestring2hex(bytestring,length) :
    arg = ('B')*length
    ans = struct.unpack(arg,bytestring)
    hexstring = [ hex(ans[i]) for i in range(length) ]
    return hexstring

def DhcpDiscover(MacAddress,TransactionId) :
    OP = b'\x01'     #Message type: Boot Request (1)
    HTYPE = b'\x01'  #Hardware type: Ethernet
    HLEN = b'\x06'   #Hardware address length: 6
    HOPS = b'\x00'   #Hops: 0
    XID = hex2bytestring(TransactionId)   #Transaction ID
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
    CHADDR5 = hex2bytestring([0x00])*192   #Client hardware address padding: 00000000000000000000
    MagicCookie = b'\x63\x82\x53\x63'  	   #Magic cookie: DHCP
    DHCPOptions1 = b'\x35\x01\x01' 	    	   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
    End = b'\xff'    #End Option

    package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + MagicCookie + DHCPOptions1 + End
    return package


def DhcpOffer(ClientMacAddress,TransactionId,ServerIp,OfferedIp,SubnetMask) :
    OP = hex2bytestring([0x02])
    HTYPE = hex2bytestring([0x01])
    HLEN = hex2bytestring([0x06])
    HOPS = hex2bytestring([0x00])
    XID = TransactionId
    SECS = hex2bytestring([0x00, 0x00])
    FLAGS = hex2bytestring([0x00, 0x00])
    CIADDR = hex2bytestring([0x00, 0x00, 0x00, 0x00])
    YIADDR = hex2bytestring(OfferedIp)
    SIADDR = hex2bytestring(ServerIp)
    GIADDR = hex2bytestring([0x00, 0x00, 0x00, 0x00])
    CHADDR1 = ClientMacAddress
    CHADDR2 = hex2bytestring([0x00, 0x00])
    CHADDR3 = hex2bytestring([0x00, 0x00, 0x00, 0x00])
    CHADDR4 = hex2bytestring([0x00, 0x00, 0x00, 0x00])
    CHADDR5 = hex2bytestring(192)
    Magiccookie = hex2bytestring([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1 = hex2bytestring([53 , 1 , 2]) # DHCP Offer
    DHCPOptions2 = hex2bytestring([1 , 4 , SubnetMask[0], SubnetMask[1], SubnetMask[2], SubnetMask[3] ]) # SubnetMask
    DHCPOptions3 = hex2bytestring([3 , 4 , ServerIp[0], ServerIp[1], ServerIp[2], ServerIp[3] ]) #192.168.1.1 router
    DHCPOptions4 = hex2bytestring([51 , 4 , 0x00, 0x01, 0x51, 0x80]) #86400s(1 day) IP address lease time
    DHCPOptions3 = hex2bytestring([3 , 4 , ServerIp[0], ServerIp[1], ServerIp[2], ServerIp[3] ]) # DHCP Server
    End = hex2bytestring([0xff])

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
    SIADDR = hex2bytestring(ServerIp)   #Next server IP address: 0.0.0.0
    GIADDR = b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    CHADDR1 = MacAddress
    CHADDR2 = b'\x00\x00'
    CHADDR3 = b'\x00\x00\x00\x00'
    CHADDR4 = b'\x00\x00\x00\x00'
    CHADDR5 = hex2bytestring(192)               	     #Client hardware address padding: 00000000000000000000
    MagicCookie = b'\x63\x82\x53\x63'  	     #Magic cookie: DHCP
    DHCPOptions1 = hex2bytestring([53 , 1 , 3])     	     #Option: (t=53,l=1) DHCP Message Type = DHCP Request
    DHCPOptions2 = hex2bytestring([50 , 4 , RequestedIp[0], RequestedIp[1], RequestedIp[2], RequestedIp[3]])   #Option: (t=50,l=4) Requested IP Adress
    DHCPOptions3 = hex2bytestring([54 , 4 , ServerIp[0], ServerIp[1], ServerIp[2], ServerIp[3]])   #Option: (t=54,l=4) DHCP Server Identifier
    End = b'\xff'   #End option

    package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + MagicCookie + DHCPOptions1 + DHCPOptions2 +  DHCPOptions3 + End

    return package


def DhcpAck(ClientMacAddress,TransactionId,ServerIp,ClientIp,SubnetMask,DNSIp,GatewayIp) :
    OP = hex2bytestring([0x02])
    HTYPE = hex2bytestring([0x01])
    HLEN = hex2bytestring([0x06])
    HOPS = hex2bytestring([0x00])
    XID = TransactionId
    SECS = hex2bytestring([0x00, 0x00])
    FLAGS = hex2bytestring([0x80, 0x00])
    CIADDR = hex2bytestring([0x00, 0x00, 0x00, 0x00])
    YIADDR = hex2bytestring(ClientIp)
    SIADDR = hex2bytestring(ServerIp)
    GIADDR = hex2bytestring([0x00, 0x00, 0x00, 0x00])
    CHADDR1 = ClientMacAddress
    CHADDR2 = hex2bytestring([0x00, 0x00])
    CHADDR3 = hex2bytestring([0x00, 0x00, 0x00, 0x00])
    CHADDR4 = hex2bytestring([0x00, 0x00, 0x00, 0x00])
    CHADDR5 = hex2bytestring(192)
    Magiccookie = hex2bytestring([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1 = hex2bytestring([53 , 1 , 5]) #DHCP ACK(value = 5)
    DHCPOptions2 = hex2bytestring([1 , 4 , SubnetMask[0], SubnetMask[1], SubnetMask[2], SubnetMask[3]]) #255.255.255.0 subnet mask
    DHCPOptions3 = hex2bytestring([3 , 4 , GatewayIp[0], GatewayIp[1], GatewayIp[2], GatewayIp[3]]) #router
    DHCPOptions4 = hex2bytestring([51 , 4 , 0x00, 0x01, 0x51, 0x80]) #86400s(1 day) IP address lease time
    DHCPOptions5 = hex2bytestring([54 , 4 , ServerIp[0], ServerIp[1], ServerIp[2], ServerIp[3]]) #DHCP server
    DHCPOptions6 = hex2bytestring([6 , 4 , DNSIp[0], DNSIp[1], DNSIp[2], DNSIp[3]]) #DHCP DNS Server
    DHCP
    End = hex2bytestring([0xff])

    package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5 + DHCPOptions6 + End

    return package
