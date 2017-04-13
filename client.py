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
        OfferedIp = DHCP.bytestring2hex(data[16:20],4)
        ServerIp = DHCP.bytestring2hex(data[20:24],4)
        OfferRecieved = True

    except socket.timeout :
        sock.sendto(package, dest)



# DHCP Acknowledgement - CLient
package = DHCP.DhcpRequest(MacAddress,TransactionId,ServerIp,OfferedIp)
sock.sendto(package,dest)

# DHCP Acknowledgement - Server
