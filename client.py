import sys
import re
import getMac
import socket

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
## Find the Mac address of the client
MacAddress = getMac.FindMac()

# Send the mac address to the server and recieve the IP
IpRecieved = False
while not IpRecieved :
    ## Send the msg to server
    UDP_IP = '255.255.255.255'
    UDP_PORT = 12345
    MESSAGE = MacAddress
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))

    ## Wait for the server to reply
    
# DHCP Discover

# DHCP Offer

# DHCP Acknowledgement - CLient

# DHCP Acknowledgement - Server
