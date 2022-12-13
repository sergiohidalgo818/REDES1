'''
    ip.py
    
    Funciones necesarias para implementar el nivel IP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
import math
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0
    y = 0x07E6       
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i] 
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    y = y & 0x00ff
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
   
    s.close()
   
    return mtu
   
def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    print("Default Gateway " + dfw)
    return struct.unpack('!I',socket.inet_aton(dfw))[0]



def process_IP_datagram(us,header,data,srcMac):
    '''
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum y comprobar que es correcto                    
                -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -TTL
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón 
                    pasando los datos (payload) contenidos en el datagrama IP.
        
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''

    ihl = bytes([data[0] & int.from_bytes(b'\x0f', "big")])
    ipid = data[4:6]
    df = bytes([data[6] & int.from_bytes(b'\x40', "big")])
    mf = bytes([data[6] & int.from_bytes(b'\x20', "big")])
    offset = bytes([data[6] & int.from_bytes(b'\x1f', "big")]) + data[7:8]
    tlive = data[8:9]
    proto = data[9:10]
    IPorg = data[12:16]
    IPdest = data[16:20]

    suma = data[:10] + bytes([0x00, 0x00]) + data[12:]

    if (chksum(suma).to_bytes(2, "big") != data[10:12]):
        return
    
    if offset!=0:
        return

    logging.debug("Longitud de la cabecera IP: " + ihl)
    logging.debug("IPID: " + ipid)
    logging.debug("TTL: " + tlive)
    logging.debug("DF: " + df)
    logging.debug("MF: " + mf)
    logging.debug("Offset: " + offset)
    logging.debug("IP origen: " + IPorg)
    logging.debug("IP destino: " + IPdest)
    logging.debug("Protocolo: " + proto)

    protocol = int.from_bytes(proto, "big")
    
    if not protocol in upperProtos:
        return
    
    f = upperProtos[protocol]
    
    f(us, header, data[int.from_bytes(data[2:4], "big"):], IPorg)
    


def registerIPProtocol(callback,protocol):
    '''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla 
            (diccionario) de protocolos de nivel superior dicha asociación. 
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un 
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra 
            llamada process_ICMP_message asocaida al valor de protocolo 1. 
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado. 
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno 
    '''
    global upperProtos

    upperProtos[struct.unpack('h',protocol)] = callback

def initIP(interface,opts=None):
    global myIP, MTU, netmask, defaultGW, ipOpts, IPID
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
            -Inicializar el valor de IPID con el número de pareja
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''

    if (initARP(interface) == -1):
        return False
    
    myIP = getIP(interface)
    MTU = getMTU(interface)
    netmask = getNetmask(interface)
    defaultGW = getDefaultGW(interface)

    ipOpts = opts

    registerCallback(process_IP_datagram, bytes([0x08,0x00]))

    IPID = 0


def sendIPDatagram(dstIP,data,protocol):
    global IPID, ipOpts
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas se debe hacer unso de la máscara de red:                  
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama 
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
          
    '''
    ip_header = bytes()
    longhead = 0

    ret = 0
    
    if ipOpts != None:
        while (len(ipOpts) % 4) != 0:
            ipOpts += bytes([0x00])
        longhead = len(ipOpts)
    

    longhead += 20
    
    versionandihl = (64 + int(longhead/4)).to_bytes(1, "big")

    typeservice = bytes([0x16])
    
    tlen = (longhead + len(data)).to_bytes(2, "big")
    
    flagsandoffset = bytes([0x00, 0x00])
    
    tlive = bytes([0x80])

    hchecksum = bytes([0x00, 0x00])

    iporg=myIP.to_bytes(4, "big")
    ipdst=dstIP.to_bytes(4, "big")

    print("Enviando datagrama IP desde ")

    print(':'.join(['{:02X}'.format(b) for b in iporg]))

    print("hasta ")

    print(':'.join(['{:02X}'.format(b) for b in ipdst]))


    if(dstIP & netmask == myIP & netmask):
        dstmac = ARPResolution(dstIP)
    else:
        dstmac = ARPResolution(defaultGW)
        
    if dstmac == None: 
            return False
        
    if len(data) > MTU - longhead:

        
        newdatalen= MTU - (MTU-longhead %8)

        datanum= math.ceil(len(data)/newdatalen)


        
        i = 0
        offsetaux=0

        while i < datanum:

            if i == datanum -1:
                flagsandoffset= int(offsetaux/8).to_bytes(2, "big")
            else:
                flagsandoffset= int(16+int(offsetaux/8)).to_bytes(2, "big")


            if i == datanum -1:
                tlen = (len(data[offsetaux-1:]) + longhead).to_bytes(2, "big")
            else:
                tlen = int(newdatalen + longhead).to_bytes(2, "big")

            
            hchecksum = bytes([0x00, 0x00])

            ip_header = versionandihl + typeservice + tlen + IPID.to_bytes(2, "big") + flagsandoffset + tlive + protocol + hchecksum + iporg + ipdst 
            if ipOpts != None:
                ip_header+= ipOpts

            hchecksum = chksum(ip_header).to_bytes(2, "big")
            
            ip_header = versionandihl + typeservice + tlen + IPID.to_bytes(2, "big") + flagsandoffset + tlive + protocol + hchecksum + iporg + ipdst
            
            if ipOpts != None:
                ip_header+= ipOpts
           
            if i == datanum -1:
                ipdatagram = ip_header + data[offsetaux-1:]
            
            else:
                ipdatagram = ip_header + data[offsetaux-1:(offsetaux+newdatalen)-1]

            
            offsetaux+=newdatalen
            
            ret+=sendEthernetFrame(ipdatagram, tlen, bytes([0x08,0x00]), dstmac)
    
    else:

        ip_header = versionandihl + typeservice + tlen + IPID.to_bytes(2, "big") + flagsandoffset + tlive + protocol + hchecksum + iporg + ipdst

        if ipOpts != None:
            ip_header+= ipOpts

        hchecksum = chksum(ip_header).to_bytes(2, "big")
            
        ip_header = versionandihl + typeservice + tlen + IPID.to_bytes(2, "big") + flagsandoffset + tlive + protocol + hchecksum + iporg + ipdst

        if ipOpts != None:
            ip_header+= ipOpts

        ipdatagram = ip_header + data

        ret+=sendEthernetFrame(ipdatagram, len(ipdatagram), bytes([0x08,0x00]), dstmac)


    IPID+=1

    if(ret <0):
        return False

    print("Datagrama IP enviado")

    return True