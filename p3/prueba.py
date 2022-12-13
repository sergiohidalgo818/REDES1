from ip import * 
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
if __name__ == "__main__":
    udp_datagram = bytes()
    data = bytes([0x13, 0xA1]*2)
    print(data)

    srcPort = bytes([0x12, 0x02])
    print(srcPort)

    dstPort = bytes([0x12, 0x92])

    udp_datagram = srcPort 


    udp_datagram += dstPort



    length = len(udp_datagram + data)
    
    length = length.to_bytes(2, "big")  
    
    
    udp_datagram += length

    udp_datagram += bytes([0x00, 0x00])
    udp_datagram += data
    print(udp_datagram)

    print(bytes ([0x4]))
    diez=8
    diezb=int(diez/4).to_bytes(1, "big")
    tst= int(64).to_bytes(1, "big") 
    test= int.from_bytes(tst, "big") + int.from_bytes(diezb, "big")

    test = 64 +int(20/4)
    print( hex(test) )


    print(math.ceil( 3699/1480))

    interface="ens33"

    print(getNetmask(interface))