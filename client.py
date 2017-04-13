import sys
import re
import socket
import random
import getMac
import DHCP

# intake argument and verify that they are correct
Arguments = sys.argv[1:]

## Check for -m flag
if Arguments[0] == '-m' or Arguments[0] == '-M' :
    Mflag = True
else :
    Mflag = False

## If Mflag is true check for the passed Mac Address
if Mflag :
    MacAddress = Arguments[1]
    pattern = re.compile('^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    if not pattern.match(MacAddress) :
        print "In-valid Mac Address."
        sys.exit(0)
    ### Conver from current format to bytes
    MacAddress = getMac.ConvertToBytes(MacAddress)

else :
    ## Find the Mac address of the client
    MacAddress = getMac.FindMac()

MAX_BYTES = 65535
Src = '0.0.0.0'
Dest = '255.255.255.255'
ClientPort = 12345
ServerPort = 12346

dest = (Dest, clientPort)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind((Src, serverPort))

# DHCP Discover
## make a transcation ID
TransactionId = [ hex(random.choice(range(256))) for i in range(4) ]

package = DHCP.DhcpDiscover(MacAddress,TransactionId)
sock.sendto(package, dest)

# DHCP Offer
OfferRecieved = False
while not OfferRecieved :
    try :
        sock.settimeout(5)
        data, address = sock.recvfrom(MAX_BYTES)
        ## Extract offered Ip and TransactionId
        TransactionId_recieved = data[4:8]
        TransactionId_recieved = DHCP.bytestring2hex(TransactionId_recieved,4)
        if TransactionId != TransactionId_recieved :
            print("Recieved Unknow message")
            continue
        MsgOptions = DHCP.ExtractOption(data)
        if (not hex(53) in MsgOptions) or MsgOptions[hex(53)] != hex(2) :
            print("Msg type not offer")
            continue
        OfferedIp = DHCP.bytestring2hex(data[16:20],4)
        ServerIp = DHCP.bytestring2hex(data[20:24],4)
        OfferRecieved = True

    except socket.timeout :
        sock.sendto(package, dest)



# DHCP Acknowledgement - CLient
package = DHCP.DhcpRequest(MacAddress,TransactionId,ServerIp,OfferedIp)
sock.sendto(package,dest)

# DHCP Acknowledgement - Server
AckRecieved = False
while not AckRecieved :
    try :
        sock.settimeout(5)
        data ,address = sock.recvfrom(MAX_BYTES)
        TransactionId_recieved = data[4:8]
        TransactionId_recieved = DHCP.bytestring2hex(TransactionId_recieved,4)
        if TransactionId != TransactionId_recieved :
            print("Recieved Unknow message")
            continue
        MsgOptions = DHCP.ExtractOption(data)
        if (not hex(53) in MsgOptions) or MsgOptions[hex(53)] != hex(5) :
            print("Msg type not Ack")
            continue
        MyIp = DHCP.bytestring2hex(data[16:20],4)
        SubnetMask = MsgOptions[hex(1)]
        GateWayIp = MsgOptions[hex(3)]
        LeaseTime =  MsgOptions[hex(51)]
        DNSIp = MsgOptions[hex(6)]
        AckRecieved = True

    except socket.timeout :
        sock.sendto(package, dest)


MyIp = [ int(MyIp[i],16) for i in range(4)]
SubnetMask = [ int(SubnetMask[i],16) for i in range(4)]
GateWayIp = [ int(GateWayIp[i],16) for i in range(4)]
DNSIp = [ int(DNSIp[i],16) for i in range(4)]
NetworkIp = [ MyIp[i] & SubnetMask[i] for i in range(4)]
Cidr = sum([bin(SubnetMask[i]).count('1') for i in range(4)])

def getbcast(ipaddr, nmask):  # Get broadcast address from ip and mask
    net = [0 for i in range(4)]
    for i in range(4):
        net[i] = int(ipaddr[i]) | 255 - int(nmask[i])  # octet or wildcard mask
    return net

BroadcastIp  = getbcast(NetworkIp,SubnetMask)

MyIp = '.'.join([str(MyIp[i]) for i in range(4)])
NetworkIp = '.'.join([str(NetworkIp[i]) for i in range(4)])
BroadcastIp = '.'.join([str(BroadcastIp[i]) for i in range(4)])
GateWayIp = '.'.join([str(GateWayIp[i]) for i in range(4)])
DNSIp = '.'.join([str(DNSIp[i]) for i in range(4)])


MyIp = MyIp + '/' + str(Cidr)

print MyIp
print NetworkIp
print BroadcastIp
print GateWayIp
print DNSIp
