from uuid import getnode as get_mac

def getMacInBytes():
    mac = str(hex(get_mac()))
    print(mac)
    mac = mac[2:]
    print(mac)
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb

def ConvertToBytes(mac) :
    ### Convert the input mac to standard format
    mac = mac.lower()
    mac = mac.split(':')
    mac = ''.join(mac)
    ### Covert the mac to bytes
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb
