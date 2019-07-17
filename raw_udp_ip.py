import socket
import struct
import pprint
import threading
import binascii

'''
IP Packet
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Data...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...

UDP Packet
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source      |   Destination   |
|      Port       |      Port       |
+--------+--------+--------+--------+
|                 |                 |
|     Length      |    Checksum     |
+--------+--------+--------+--------+
|
|          data octets ...
+---------------- ...

UDP Pseudo Header
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|          source address           |
+--------+--------+--------+--------+
|        destination address        |
+--------+--------+--------+--------+
|  zero  |protocol|   UDP length    |
+--------+--------+--------+--------+
'''

VERSION_OFF     = 0
IHL_OFF         = VERSION_OFF
DSCP_OFF        = IHL_OFF + 1
ECN_OFF         = DSCP_OFF
IP_LENGTH_OFF   = ECN_OFF + 1
ID_OFF          = IP_LENGTH_OFF + 2
FLAGS_OFF       = ID_OFF + 2
OFFSET_OFF      = FLAGS_OFF
TTL_OFF         = FLAGS_OFF + 2
PROTO_OFF       = TTL_OFF + 1
IP_CHECKSUM_OFF = PROTO_OFF + 1
SRC_IP_OFF      = IP_CHECKSUM_OFF + 2
DST_IP_OFF      = SRC_IP_OFF + 4

SRC_PORT_OFF    = 0
DST_PORT_OFF    = SRC_PORT_OFF + 2
UDP_LEN_OFF     = DST_PORT_OFF + 2
UDP_CHECKSUM_OFF= UDP_LEN_OFF + 2


def parse_ip_packet(ip_packet):
    info = {}
    info['version']     = ip_packet[VERSION_OFF] >> 4
    info['IHL']         = ip_packet[IHL_OFF] & 0x0F
    info['DSCP']        = ip_packet[DSCP_OFF] >> 2
    info['ECN']         = ip_packet[ECN_OFF] & 0x03
    info['length']      = ip_packet[IP_LENGTH_OFF] << 8 | ip_packet[IP_LENGTH_OFF + 1]
    info['ID']          = ip_packet[ID_OFF] << 8 | ip_packet[ID_OFF + 1]
    info['flags']       = ip_packet[FLAGS_OFF] >> 5
    info['offset']      = (ip_packet[OFFSET_OFF] & 0b11111) << 8 | ip_packet[OFFSET_OFF + 1]
    info['TTL']         = ip_packet[TTL_OFF]
    info['protocol']    = ip_packet[PROTO_OFF]
    info['checksum']    = ip_packet[IP_CHECKSUM_OFF] << 8 | ip_packet[IP_CHECKSUM_OFF + 1]
    info['src_ip']      = '{}.{}.{}.{}'.format(*struct.unpack('BBBB', ip_packet[SRC_IP_OFF : SRC_IP_OFF + 4]))
    info['dst_ip']      = '{}.{}.{}.{}'.format(*struct.unpack('BBBB', ip_packet[DST_IP_OFF : DST_IP_OFF + 4]))
    info['data']        = ip_packet[info['IHL'] * 4 : info['length']] # variable header length
    return info


def parse_udp_packet(udp_packet):
    info = {}
    info['src_port']    = udp_packet[SRC_PORT_OFF] << 8 | udp_packet[SRC_PORT_OFF + 1]
    info['dst_port']    = udp_packet[DST_PORT_OFF] << 8 | udp_packet[DST_PORT_OFF + 1]
    info['length']      = udp_packet[UDP_LEN_OFF] << 8 | udp_packet[UDP_LEN_OFF + 1]
    info['checksum']    = udp_packet[UDP_CHECKSUM_OFF] << 8 | udp_packet[UDP_CHECKSUM_OFF + 1]
    info['data']        = udp_packet[8 : info['length']]
    return info


def craft_ip4_packet(   data, 
                        src_ip      ='127.0.0.1', 
                        dst_ip      ='127.0.0.1',
                        ip_ihl      =5,
                        ip_tos      =0,
                        ip_id       =1313,
                        ip_flags    =0,
                        ip_offset   =0,
                        ip_ttl      =255,
                        ip_proto    =17):
    ip_ver = 4
    ip_ver_ihl = ip_ver << 4 | ip_ihl
    ip_total_len = 4 * ip_ihl + len(data)
    ip_flags_off = ip_flags << 13 | ip_flags
    src_ip = ip2uint(src_ip)
    dst_ip = ip2uint(dst_ip)
    ip_checksum = 0
    ip_header = struct.pack('!BBHHHBBHII', ip_ver_ihl, ip_tos, ip_total_len,
                            ip_id, ip_flags_off,
                            ip_ttl, ip_proto, ip_checksum,
                            src_ip,
                            dst_ip)
    ip_checksum = checksum_func(ip_header)
    ip_header = struct.pack('!BBHHHBBHII', ip_ver_ihl, ip_tos, ip_total_len,
                            ip_id, ip_flags_off,
                            ip_ttl, ip_proto, ip_checksum,
                            src_ip,
                            dst_ip)
    return ip_header + data


def craft_udp_packet(data, src_addr, dst_addr):
    if type(data) != bytes:
        data = bytes(data.encode('utf-8'))
    src_ip, dst_ip     = ip2uint(src_addr[0]), ip2uint(dst_addr[0])
    src_port, dst_port = src_addr[1], dst_addr[1]
    udp_length = 8 + len(data)
    protocol = socket.IPPROTO_UDP
    pseudo_header = struct.pack('!IIBBH', src_ip, dst_ip, 0, protocol, udp_length)
    checksum = 0
    udp_header = struct.pack('!4H', src_port, dst_port, udp_length, checksum)
    checksum = checksum_func(pseudo_header + udp_header + data)
    udp_header = struct.pack('!4H', src_port, dst_port, udp_length, checksum)
    return udp_header + data


def send_udp(data, src_addr, dst_addr=('127.0.0.1', 13228)):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
        udp_packet = craft_udp_packet(data, src_addr, dst_addr)
        ip_packet = craft_ip4_packet(udp_packet, src_addr[0], dst_addr[0])
        sock.sendto(ip_packet, dst_addr)


def ip2uint(ip_str):
    arr = [int(x) for x in ip_str.split('.')]
    return arr[0] << 24 | arr[1] << 16 | arr[2] << 8 | arr[3]


def checksum_func(data):
    checksum = 0
    if len(data) & 1:
        data += b'\x00'
    for i in range(0, len(data), 2):
        checksum += data[i] << 8 | data[i + 1]
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = ~checksum & 0xFFFF
    return 0xFFFF if checksum == 0 else checksum

