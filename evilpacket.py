from scapy.all import *
import string

def randomstring(length=-1):
    '''
    generate a random string, default length is random
    '''
    if length<=0:
        length=random.randint(1,255)
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


def splitbylength(s,length):
    '''
    split a string by length
    '''
    return [s[i:i+length] for i in range(0, len(s), length)]

def tcpsegmentation(originalpacket,breakby):
    '''
    split a packet into segments by tcp segmentation
    '''
    payloadsplited=splitbylength(bytes(originalpacket[TCP].payload),breakby)
    packetslist=[]
    sent=0
    for payload in payloadsplited:
        packet=originalpacket.copy()
        del packet[Raw]
        packet[TCP]/=payload
        packet[TCP].seq=originalpacket[TCP].seq+sent
        sent+=len(payload)
        packetslist.append(packet)
    return packetslist

def ipfragmentation(originalpacket,breakby):
    '''
    split a packet into fragments by ip fragmentation
    '''
    return fragment(originalpacket,breakby)

def setttl(packet,ttl):
    '''
    set ttl of a packet
    '''
    packet[IP].ttl=ttl
    return packet


def garbagepacket(originalpacket):
    '''
    generate a garbage packet by changing a packet's payload
    '''
    packet=originalpacket.copy()
    del packet[Raw]
    packet[TCP]/=randomstring()
    return packet

def rstpacket(originalpacket):
    '''
    generate a rst packet by changing a packet's flags
    '''
    packet=originalpacket.copy()
    packet[TCP].flags='R'
    return packet

def fuckupchecksum(originalpacket):
    '''
    fuckup a packet's checksum
    '''
    packet=originalpacket.copy()
    #calculate its chksum first
    del packet[IP].chksum
    originalchksum=packet.__class__(bytes(packet)).chksum
    fuckedupchksum=(originalchksum+RandShort()) % 65535
    packet.chksum=fuckedupchksum
    return packet

def fuckupack(originalpacket):
    '''
    fuckup a packet's ack
    '''
    packet=originalpacket.copy()
    packet[TCP].ack=(packet[TCP].ack+RandShort())%65535
    return packet

def setflags(originalpacket,flags):
    '''
    fuckup a packet's flags
    '''
    packet=originalpacket.copy()
    packet[TCP].flags=flags#'FRAPUEN'
    return packet