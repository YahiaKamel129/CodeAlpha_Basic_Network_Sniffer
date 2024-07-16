from scapy.all import *
from scapy.layers import http

def MySniff(NetworkPacket):
    if NetworkPacket.haslayer(http.HTTPRequest):
        S_IP = NetworkPacket[IP].src
        S_P =  str(NetworkPacket.sport)
        S_M = NetworkPacket.src

        D_IP = NetworkPacket[IP].dst
        D_P =  str(NetworkPacket.dport)
        D_M = NetworkPacket.dst
        Packet_Type = NetworkPacket.type
        #2048 = IPV4
        Packet_Length = len(NetworkPacket)
        Packet_Protocol = NetworkPacket[IP].proto
        # 6 = TCP

        print(" ---------------------------------------------- ")
        print(" [+] * Sniffer Has Started Succesfully!! * [+] ")
        print(" ---------------------------------------------- ")

        print("Packet_Type ", Packet_Type)
        print("packet_length ", Packet_Length)
        print("Packet_Protocol ", Packet_Protocol)

        print("______Source Information______:")
        print("Source IP ", S_IP)
        print("Source Port Number ", S_P)
        print("Source MAC Address ", S_M)

        print("\n______Destination Information______:")
        print("Destination IP ", D_IP)
        print("Destination Port Number ", D_P)
        print("Destination MAC Address ",D_M)
        
        print("\n______About Data______:")
        print("[+] ",NetworkPacket[http.HTTPRequest].Host + NetworkPacket[http.HTTPRequest].Path )
        if(NetworkPacket.haslayer(Raw)):
            request = NetworkPacket[Raw].load
            print("[*_*] ->->->->->->->", request , "<-<-<-<-<-<-<- [*_*]")




sniff(iface="Wi-Fi", store=False, prn=MySniff)