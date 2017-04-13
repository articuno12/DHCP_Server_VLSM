from math import pow, ceil, log

def get_info(mac):

    def min_pow2(x):  # how many bits do we need to borrow
        z = log(x, 2)  # to cover number of hosts
        if int(z) != z:  # in math language:
            z = ceil(z)  # to which integer power do
        return int(z)  # we need to raise 2 to get the number that is ge "x"


    def getmask(cidr):  # ex. 24 -> 255.255.255.0
        arr = [0 for i in range(4)]  # creating list of four 0s
        y = int(cidr / 8)  # how many octets of 255
        if y > 0:  # if mask < 8
            for z in range(y):
                arr[z] = 255
            arr[z + 1] = int(256 - pow(2, 8 - (cidr - 8 * y)))
        else:
            arr[0] = 256 - pow(2, 8 - cidr)
        return arr


    def getnet(ipaddr, nmask):  # Get network address from ip and mask
        net = [0 for i in range(4)]
        for i in range(4):
            net[i] = int(ipaddr[i]) & int(nmask[i])  # octet and mask
        return net


    def getfirst(ipaddr):  # Get first usable address from ip and mask
        addr = ipaddr[:]  # list is mutable, not to change the global value
        addr[3] = int(addr[3]) + 1
        return addr


    def getlast(ipaddr, nmask):  # Get last usable address from ip and mask
        addr = getbcast(ipaddr, nmask)
        addr[3] -= 1
        return addr


    def getbcast(ipaddr, nmask):  # Get broadcast address from ip and mask
        net = [0 for i in range(4)]
        for i in range(4):
            net[i] = int(ipaddr[i]) | 255 - int(nmask[i])  # octet or wildcard mask
        return net


    def getnextaddr(ipaddr, nmask):
        ipaddr = getbcast(ipaddr, nmask)
        for i in range(4):
            if ipaddr[3 - i] == 255:
                ipaddr[3 - i] = 0
                if ipaddr[3 - i - 1] != 255:
                    ipaddr[3 - i - 1] += 1
                    break
            else:
                ipaddr[3 - i] += 1
                break
        return ipaddr


    def getnextip(ipaddr):
        for i in range(4):
            if ipaddr[3 - i] == 255:
                ipaddr[3 - i] = 0
                if ipaddr[3 - i - 1] != 255:
                    ipaddr[3 - i - 1] += 1
                    break
            else:
                ipaddr[3 - i] += 1
                break
        return ipaddr


    def lessthan(ip1,ip2):#if ip1 less than or equal to ip2
        for i in range(0,4):
            if(ip1[i] <= ip2[i]):
                pass
            else:
                return False
        return True

    def norm(ipaddr):
        addr = ipaddr[:]
        for i in range(len(addr)):
            addr[i] = str(addr[i])
        return ".".join(addr)


    def vlsm(ipaddr, hosts):

        bits = 0

        for x in range(len(hosts)):
            bits = min_pow2(hosts[x][0] + 2)
            ipaddr = getnet(ipaddr, getmask(int(32 - bits)))
            #" SUBNET: %d NEEDED: %3d (%3d %% of) ALLOCATED %4d ADDRESS: %15s :: %15s - %-15s :: %15s MASK: %d (%15s)" % \
            info[str(hosts[x][1])] = [x + 1,
                   hosts[x][0],
                   (hosts[x][0] * 100) / (int(pow(2, bits)) - 2),
                   int(pow(2, bits)) - 2,
                   ipaddr,
                   getfirst(ipaddr),
                   getfirst(ipaddr),
                   getlast(ipaddr, getmask(int(32 - bits))),
                   norm(getbcast(ipaddr, getmask(int(32 - bits)))),
                   32 - bits,
                   norm(getmask(int(32 - bits)))]


            ipaddr = getnextaddr(ipaddr, getmask(int(32 - bits)))


    def getip(mac): #returns ip for client and dns server
        args=[]
        with open('subnets.conf', 'r') as f:
            for line in f:
                args.append(line)

        ip = args[0].split("/")[0].split(".")   # 192.168.1.0/24 2 8 22 54  -> list of str ['192','168','1','0']
        cidr = int(args[0].split("/")[1])       # 192.168.1.0/24 2 8 22 54  -> str 24
        mask = getmask(cidr)                    #                       24  -> list of int [255,255,255,0]
        total_hosts = 0
        n = int(args[1])
        labs={}

        for i in range(2,2+n):
            labs[str(str(args[i]).split(':')[0])]= int(str(args[i]).split(':')[1])
            total_hosts+= int(str(args[i]).split(':')[1])

        for x in range(len(ip)):  # list of str ['192','168','1','0'] ->
            ip[x] = int(ip[x])  # list of int [192,168,1,0]

        if total_hosts > (pow(2, 32 - cidr) - 2):
            Error = "Too many hosts"

        if (pow(2, 32 - cidr) - 2 - total_hosts) > 0:
            labs['others'] = pow(2, 32 - cidr) - 2 - total_hosts
            no_others = False
        else :
            no_others = True
            DHCP_IP = None
            Error = "Ip cant be assigned to DHCP server"

        t = [(labs[i],i) for i in labs]
        t = sorted(t,reverse=True)


        vlsm(getnet(ip, mask), t)

        macs={}
        Error = None
        for i in range(2+n,len(args)):
            macs[str(args[i]).split(' ')[0]] = str(args[i]).split(' ')[1]

        if(macs.has_key(mac)):
            l = macs.get(mac)
        else:
            if(no_others):
                Error = "IP cant be assigned"
            else:
                l = 'others'
                Error = None

        if Error:
            return 0,Error
        else:
            if(l != 'others'):
                if lessthan(getnextip(info[l][6]), info[l][7]):
                    client_ip = info[l][6] = getnextip(info[l][6])
                else:
                    client_ip = None

                dhcp_ip = getnextip(info['others'][5])
                mask = info[l][10]
                gateway_ip = dns_ip = info[l][5]
            else:
                dhcp_ip = getnextip(info['others'][5])
                if lessthan(getnextip(info[l][6]), info[l][7]):
                    if(getnextip(info[l][6])!= dhcp_ip):
                        client_ip = info[l][6] = getnextip(info[l][6])
                    else:
                        if lessthan(dhcp_ip, info[l][7]):
                            client_ip = info[l][6] = getnextip(info[l][6])
                        else :
                            client_ip = None
                    if client_ip:
                        mask = info[l][10]
                        gateway_ip = dns_ip = info[l][5]
                else:
                    client_ip = None
            if client_ip:
                client_ip = norm(client_ip)
                dhcp_ip = norm(dhcp_ip)
                gateway_ip = norm(gateway_ip)
                dns_ip = norm(dns_ip)
            else:
                Error = "IP cant be assigned"

        if Error :
            return 0,Error
        else:
            return 1,{'ClientIP':client_ip ,'mask':mask , 'DHCPIP':dhcp_ip , 'GatewayIP':gateway_ip , 'DNSIP':dns_ip }
    info = {}
    return getip(mac)
