import struct
import fcntl


if __name__ == "__main__":
    udp_datagram = bytes()
    data = bytes([0x13, 0xA1]*2)
    print(data)

    srcPort = bytes([0x12, 0x02])
    print(srcPort)

    dstPort = bytes([0x12, 0x92])

    udp_datagram = srcPort 


    udp_datagram += dstPort

    print(udp_datagram)


    length = len(udp_datagram + data)
    print(hex(length)[:15])
    
    length = bytes(hex(length).encode())   
    
    print(str(length))
    
    udp_datagram += length
    print(udp_datagram)

    udp_datagram += bytes([0x00, 0x00])

