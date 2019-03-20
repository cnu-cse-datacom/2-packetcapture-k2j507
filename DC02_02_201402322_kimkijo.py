import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("<<<<<<Packet Capture Start>>>>>>")
    print("======ethernet header======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version", ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

def parsing_ip_header(data):
    ip_header = struct.unpack("!1B1B1H1H1H1B1B1H4s4s", data)
    ip_version_IHL = ip_header[0]
    ip_service_codepoint = ip_header[1]
    ip_total_length = ip_header[2]
    ip_identification = ip_header[3]
    ip_fragment_offset = ip_header[4]
    ip_time_to_live = ip_header[5]
    ip_protocol = ip_header[6]
    ip_hdr_checksum = ip_header[7]
    ip_src_address = ip_header[8]
    ip_dest_address = ip_header[9]
    flags = (ip_fragment_offset >> 0xd) & 0x7

    print("======ip_header======")
    print("ip_version:",(ip_version_IHL & 0xf0) >> 0x4)
    print("ip_length:",(ip_version_IHL & 0xf))
    print("differentiated_service_codepoint:",(ip_service_codepoint & 0xfc) >> 0x2)
    print("explicit_congestion_notification:",(ip_service_codepoint & 0x3))
    print("total_length:", ip_total_length)
    print("flags", hex(flags))
    print(">>>reserved_bit:",(flags & 0x4) >> 0x2)
    print(">>>not_fragments",(flags & 0x2) >> 0x1)
    print(">>>fragments:",(flags & 0x1))
    print(">>>fragments_offset:", ip_fragment_offset & 0x1FFF)
    print("Time to live:",ip_time_to_live)
    print("protocol",ip_protocol)
    print("header checksum:", hex(ip_hdr_checksum))
    print("source_ip_address:", socket.inet_ntoa(ip_src_address))
    print("Destination_ip_address:", socket.inet_ntoa(ip_dest_address))

   
def parsing_ip_protocol(data):
    ip_header = struct.unpack("!1B1B1H1H1H1B1B1H4s4s", data)
    ip_protocol = ip_header[6]
    
    if ip_protocol == 0x6:
        return 0x6
    elif ip_protocol == 0x11:
        return 0x11



def parsing_tcp_header(data):
    tcp_header = struct.unpack("1H1H1I1I1B1B1H1H1H",data)
    tcp_src_port = tcp_header[0]
    tcp_dest_port = tcp_header[1]
    tcp_seq_num = tcp_header[2]
    tcp_ack_num = tcp_header[3]
    tcp_offset_reserved = tcp_header[4]
    tcp_flag = tcp_header[5]
    tcp_window = tcp_header[6]
    tcp_checksum = tcp_header[7]
    tcp_urgent_pointer = tcp_header[8]

    print("@@@@@@@@@@@@@@@@@@tcp_header@@@@@@@@@@@@@@@@@@")
    print("src_port:", tcp_src_port)
    print("des_port:", tcp_dest_port)
    print("seq_num:", tcp_seq_num)
    print("ack_num:", tcp_ack_num)
    print("header_len:", (tcp_offset_reserved & 0xf0) >> 0x4)
    print("flags:", tcp_flag)
    print(">>>reserved:", (tcp_offset_reserved & 0xf))
    print(">>>nonce:", ((tcp_flag) & 128) >> 0x7)
    print(">>>cwr:", (tcp_flag) & 0x40 >> 0x6)
    print(">>>urgent:", (tcp_flag) & 0x20 >> 0x5)
    print(">>>ack:", (tcp_flag) & 0x10 >> 0x4)
    print(">>>push:", (tcp_flag) & 0x8 >> 0x3)
    print(">>>reset:", (tcp_flag) & 0x4 >> 0x2)
    print(">>>syn:", (tcp_flag) & 0x2 >> 0x1)
    print(">>>fin:", (tcp_flag) & 0x1)
    print("window_size_value:", tcp_window)
    print("checksum:", tcp_checksum)
    print("urgent_pointer:", tcp_urgent_pointer)

def parsing_udp_header(data):
    udp_header = struct.unpack("!1H1H1H1H", data)
    udp_src_port = udp_header[0]
    udp_dest_port = udp_header[1]
    udp_length = udp_header[2]
    udp_checksum = udp_header[3]


    print("##################udp_header####################")
    print("src_port:", udp_src_port)
    print("dst_port:", udp_dest_port)
    print("leng:", udp_length)
    print("header checksum:", hex(udp_checksum))


recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))

while True:
    data = recv_socket.recvfrom(20000)
    ip_protocol = parsing_ip_protocol(data[0][14:34])
    if ip_protocol == 6:
        parsing_ethernet_header(data[0][0:14])
        parsing_ip_header(data[0][14:34])
        parsing_tcp_header(data[0][34:54])
    elif ip_protocol == 17:
        parsing_ethernet_header(data[0][0:14])
        parsing_ip_header(data[0][14:34])
        parsing_udp_header(data[0][34:42])
