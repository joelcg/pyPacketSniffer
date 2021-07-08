import struct
import socket

# merubah data mac address ke format yang mudah dibaca; convention umum -> AA:BB:CC:DD:EE:FF
def get_mac_addr(mac_addr):
    # diformat menjadi 2 digits {02x} dimasing" posisi xx | xx:xx:xx:xx:xx:xx
    string = map('{02x}'.format, mac_addr)
    # setelah diformat, digabung kembali, kemudian return
    return ':'.join(string)#.upper()

# ethernet frame
def ethernet(raw_data):
    # pemecahan header ethernet frame dengan format!: 6byte 3byte H2byte [data_payload]
    dst_mac_addr, src_mac_addr, type = struct.unpack('! 6s 3s H', data[:14])
    # return data yang dipecah dan data_payload
    return get_mac_addr(dst_mac_addr), get_mac_addr(src_mac_addr), socket.hton(type), data[14:]
