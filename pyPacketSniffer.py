from scapy.all import *
import socket, datetime, time, threading
import PySimpleGUI as sg

def capture(packet):
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
                print("Application Layer Protocol: " +
                      port_proto(int(packet.sport)))
            elif packet.dport != None:
                print("Application Layer Protocol: " +
                      port_proto(int(packet.dport)))
            print("\n")
            
    if packet.haslayer(UDP):
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
                print("Application Layer Protocol: " + 
                      port_proto(int(packet.dport)))
            elif packet.dport != None:
                print("Application Layer Protocol: " + 
                      port_proto(int(packet.sport)))
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
            print("Request: " + str(packet[ARP].psrc) + " is asking about " + 
                  str(packet[ARP].pdst))
        elif packet[ARP].op == 2:
            print("Response: " + str(packet[ARP].hwsrc) + " has address " + 
                  str(packet[ARP].psrc))
        print("\n")
        
    else: 
        return "Unrecognized segment or packet recorded. \n"

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
        return "Bootstrap Protocol (BOOTP) - Server / ", \
            "Dynamic Host Configuration Protocol (DHCP)"
    elif port == 68:
        return "Bootstrap Protocol (BOOTP) - Client / ", \
            "Dynamic Host Configuration Protocol (DHCP)"
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

def main():
    menu_def = [['&Help', [ 'About']]]
    layout = [
        [sg.Text('Welcome To pyPacketSniffer', 
                 font=("Helvetica", 14))],
        [sg.Menu(menu_def)],
        [sg.Text('Stop Sniffing after (sec)', size =(20, 1)), 
         sg.Input(key='timeout')],
        [sg.Button('Start Sniffing!')],
        [sg.Button('Quit!')]
    ]
    sg.theme('Dark Blue 3')
    win = sg.Window('pyPacketSniffer', layout)
    
    while True:
        event, value = win.read(timeout=100)
        if (event == sg.WIN_CLOSED or
            event == 'Quit!'):
            win.close()
            break
        
        elif event == 'Start Sniffing!':
            sg.Print('Re-routing the stdout', do_not_reroute_stdout=False)
            print = sg.Print
            sniff(prn=capture, timeout=int(value['timeout']))

        elif event == 'About':
            layout = [
                [sg.Text('About', 
                         font=("Helvetica", 14))],
                [sg.Text("A simple and purely python-based network and ",
                         font=("Helvetica", 11))],
                [sg.Text("transport layer packet sniffing tool with a ",
                         font=("Helvetica", 11))],
                [sg.Text("simple GUI and an easy to read data by ", 
                         font=("Helvetica", 11))],
                [sg.Text("design.", font=("Helvetica", 11))],
                [sg.Button('Back!')]
            ]
            sg.theme('Dark Blue 3')
            win2 = sg.Window('pyPacketSniffer', layout)
            while True:
                event2, value2 = win2.read(timeout=100)
                if (event2 == sg.WIN_CLOSED or
                    event2 == 'Back!'):
                    win2.close()
                    break
                
    win.close()  
    
if __name__ == '__main__':
    main()