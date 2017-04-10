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
