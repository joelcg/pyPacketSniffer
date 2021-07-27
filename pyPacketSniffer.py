from scapy.all import *
import socket, datetime, os, time

def main(packet):
    clock = datetime.datetime.now()
    if packet.haslayer(TCP):
        if socket.gethostbyname(socket.gethostname()) == packet[IP].dst:
            print("[" + str(clock) + "]")
            print("Transport Layer: TCP")
            print(str(len(packet[TCP])) + " bytes in.")
            print("Source MAC: " + str(packet.src))
            print("Source IP: " + str(packet[IP].src))
            print("Source Port: " + str(packet.sport))
            print("Destination MAC: " + str(packet.dst))
            print("Destination IP: " + str(packet[IP].dst))
            print("Destination Port: " + str(packet.dport))
            if packet.sport != None:
                print("Application Layer Protocol: " + port_proto(int(packet.sport)))
            elif packet.dport != None:
                print("Application Layer Protocol: " + port_proto(int(packet.dport)))
            print("\n")
            
    elif packet.haslayer(UDP):
        if socket.gethostbyname(socket.gethostname()) == packet[IP].dst:
            print("[" + str(clock) + "]")
            print("Transport Layer Protocol: UDP")
            print(str(len(packet[UDP])) + " bytes in.")
            print("Source MAC: " + str(packet.src))
            print("Source IP: " + str(packet[IP].src))
            print("Source Port: " + str(packet.sport))
            print("Destination MAC: " + str(packet.dst))
            print("Destination IP: " + str(packet[IP].dst))
            print("Destination Port: " + str(packet.dport))
            if packet.sport != None:
                print("Application Layer Protocol: " + port_proto(int(packet.dport)))
            elif packet.dport != None:
                print("Application Layer Protocol: " + port_proto(int(packet.sport)))
            print("\n")
        
    if packet.haslayer(ICMP):
        if socket.gethostbyname(socket.gethostname()) == packet[IP].dst:
            print("[" + str(clock) + "]")
            print("Network Layer Protocol: ICMP")
            print(str(len(packet[ICMP])) + " bytes in.")
            print("IP Version: " + str(packet[IP].version))
            print("Source MAC: " + str(packet.src))
            print("Source IP: " + str(packet[IP].src))
            print("Destination MAC: " + str(packet.dst))
            print("Destination IP: " + str(packet[IP].dst))
            print("\n")
        
    elif packet.haslayer(ARP):
        print("[" + str(clock) + "]")
        print("Network Layer Protocol: ARP")
        print(str(len(packet[ARP])) + " bytes in.")
        if packet[ARP].op == 1:
            print("Request: " + str(packet[ARP].psrc) + " is asking about " + str(packet[ARP].pdst))
        elif packet[ARP].op == 2:
            print("Response: " + str(packet[ARP].hwsrc) + " has address " + str(packet[ARP].psrc))
        print("\n")
    
    # else: 
    #     print("Unrecognized segment or packet recorded. \n")

def port_proto(port):
    # HANYA BEBERAPA PROTOKOL
    if port == 20:
        return "File Transfer Protocol (FTP) - Data"
    elif port == 21:
        return "File Transfer Protocol (FTP) - Control"
    elif port == 22:
        return "Secure Shell Protocol (SSH)"
    elif port == 23:
        return "Telnet Protocol (Telnet)"
    elif port == 25:
        return "Simple Mail Transfer Protocol (SMTP)"
    elif port == 53:
        return "Domain Name System(DNS) Protocol"
    elif port == 67:
        return "Bootstrap Protocol (BOOTP) - Server / Dynamic Host Configuration Protocol (DHCP)"
    elif port == 68:
        return "Bootstrap Protocol (BOOTP) - Client / Dynamic Host Configuration Protocol (DHCP)"
    elif port == 80:
        return "Hypertext Transfer Protocol (HTTP)"
    elif port == 115:
        return "Simple File Transfer Protocol (SFTP)"
    elif port == 118 or port == 156:
        return "Structured Query Language (SQL) Services"
    elif port == 121:
        return "Simple Network Management Protocol (SNMP)"
    elif port == 194:
        return "Internet Relay Chat (IRC)"
    elif port == 319:
        return "Precision Time Protocol (PTP) Event"
    elif port == 320:
        return "Precision Time Protocol (PTP) General"
    elif port == 443:
        return "Hypertext Transfer Protocol Secure (HTTPS)"
    else:
        return str(port)
            
if __name__ == '__main__':
	sniff(prn=main)