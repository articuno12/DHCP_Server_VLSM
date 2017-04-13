import sys
import re
import socket
import random
import getMac
import DHCP

MAX_BYTES = 65535
Src = "192.168.1.1"
Dest = "255.255.255.255"
clientPort = 12345
serverPort = 12346

print("DHCP server is running.")
print("_________________________________________________")
dest = (Dest, serverPort)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind(('', clientPort))

Active = []
Offered = {}
while True :
    # Recieve messages
    data, address = sock.recvfrom(MAX_BYTES)
    print("got something")
    try :
        TransactionId = DHCP.bytestring2hex(data[4:8],4)
    except Exception as e :
        print("Exception raised in TransactionId")
        print e,e.args
        continue
    MsgOptions = DHCP.ExtractOption(data)
    if not hex(53) in MsgOptions :
        continue

    if not TransactionId in Active :
        if MsgOptions[hex(53)][0]!= hex(1) :
            continue
        # DHCP Discover
        Active.append(TransactionId)
        ClientMacAddress = DHCP.bytestring2hex(data[28:34],6)
        Mac_str = []
        for i in range(6) :
            temp = ClientMacAddress[i][2:]
            temp = temp.upper()
            while len(temp) < 2 :
                temp = '0' + temp
            Mac_str.append(temp)

        Mac_str = ':'.join(Mac_str)
        print('\nGot DHCPDISCOVER : Transaction Id ' + str(TransactionId) + ' Mac  ' + Mac_str)

        # Get new Ip to be allocated to the client
        OfferedIp,SubnetMask,GateWayIp,DNSIp = vlsm()
    #
    #     # DHCP Offer
    #     # If new Ip is not available
    #     if OfferedIp[0] == -1 :
    #         print('\n DHCP Declined : Transaction Id ' + str(TransactionId) + ' Mac  ' + Mac_str)
    #         package = DHCP.DhcpDecline(ClientMacAddress,TransactionId,Src)
    #         sock.sendto(package,dest)
    #         del Active[TransactionId]
    #         continue
    #
    #     Offered[str(TransactionId)] = (ClientMacAddress,TransactionId,Src,OfferedIp,SubnetMask,DNSIp,GatewayIp)
    #     package = DHCP.DhcpOffer(ClientMacAddress,TransactionId,Src,OfferedIp,SubnetMask,DNSIp,GatewayIp)
    #     sock.sendto(package,dest)
    #
    # else :
    #     # DHCP Request
    #     if MsgOptions[hex(53)][0]!= hex(3) :
    #         continue
    #     (ClientMacAddress,TransactionId,Src,OfferedIp,SubnetMask,DNSIp,GatewayIp) = Offered[str(TransactionId)]
    #
    #     # DHCP Ack
    #     package = DHCP.DhcpAck(ClientMacAddress,TransactionId,Src,OfferedIp,SubnetMask,DNSIp,GatewayIp)
    #     sock.sendto(package,dest)
