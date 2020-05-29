import dpkt
import ipaddress
import sys


# Get only the ARP packets
def getarppackets(pcap, arppack):
    for ts, buf in pcap:
        eth = buf[0:14]
        ethtype = eth[12:14]
        arptype = (0x0806).to_bytes(2, byteorder='big')
        if ethtype == arptype:
            # It is arp type
            arppack.append(buf[14:42])
    print("Number of ARP Packets: ", end=" ")
    print(len(arppack))

# Get response type
def getarpresponse(arppack):
    resplist = []
    for x in arppack:
        responsetype = int.from_bytes(x[6:8], byteorder='big')
        resplist.append(responsetype)
    return resplist


# Put it in Mac Addr
def getMacAdd(smac):
    addr = []
    for a in smac:
        addr.append(a)
    for ind in range(0, len(addr) - 1):
        print('{:x}:'.format(addr[ind]), end=" ")
    print('{:x}'.format(addr[-1]))


# Output Arppack
def arpout(arppack, ind):
    a = arppack[ind]
    print("Hardware Type: ", end=" ")
    print("Ethernet", end=" ")
    hardtype = a[0:2]
    htype = int.from_bytes(hardtype, byteorder='big')
    print('(' + str(htype) + ')')
    # Protocol Type
    print("Protocol Type: ", end=" ")
    prototype = int.from_bytes(a[2:4], byteorder='big')
    print(hex(prototype))
    # Hardware Size
    print("Hardware Size: ", end=" ")
    hsize = a[4]
    print(hsize)
    # Protocol Size
    print("Protocol Size: ", end=" ")
    psize = a[5]
    print(psize)
    # Opcode
    print("Opcode: ", end=" ")
    op = int.from_bytes(a[6:8], byteorder='big')
    if op == 1:
        print('request (', end="")
    else:
        print('reply (', end='')
    print(op, end="")
    print(")")
    # Sender MAC Address
    print("Sender MAC Address: ", end=" ")
    smac = a[8:14]
    getMacAdd(smac)
    # Sender IP Address
    print("Sender IP Address: ", end=" ")
    sip = int.from_bytes(a[14:18], byteorder='big')
    sendip = ipaddress.ip_address(sip)
    print(sendip)
    # Target MAC Address
    print("Target MAC Address: ", end=" ")
    tmac = a[18:24]
    getMacAdd(tmac)
    # Target IP Address
    print("Target IP Address: ", end=" ")
    tip = int.from_bytes(a[24:], byteorder='big')
    targetip = ipaddress.ip_address(tip)
    print(targetip)
    print("***********************************************************************")

# Get arp reply
def getnumval(responselist):
    val = 0
    for num in range(0, len(responselist)):
        if responselist[num] == 2:
            val = num
            break
    return val


def main():
    print("Please input pcap file")
    x = input()
    file = open(x, 'rb')
    #file = open("assignment3_my_arp.pcap", 'rb')
    pcap = dpkt.pcap.Reader(file)
    arppack = []
    getarppackets(pcap, arppack)
    print("---------------------------------------------------------")
    for ind in range(0, len(arppack)):
        arpout(arppack, ind)
    # arpoutput(arppack)
    print("************************************One ARP Exchange*****************************************************")
    responselist = getarpresponse(arppack)
    ind = getnumval(responselist)
    i = 0
    packetid = 0
    while i < ind:
        requestpacket = arppack[i]
        replypacket = arppack[ind]
        packetnum = int.from_bytes(requestpacket[24:], byteorder='big')
        bigpacketnum = int.from_bytes(replypacket[14:18], byteorder='big')
        if packetnum == bigpacketnum:
            packetid = i
            break
        i = i + 1
    print("ARP REQUEST--------------------------------------------------------------------")
    arpout(arppack, packetid)
    print("ARP RESPONSE--------------------------------------------------------------------")
    arpout(arppack, ind)


if __name__ == "__main__":
    main()
