import sys
import socket
import time
import threading
import pprint
import struct
import raw_udp_ip

AUTH_TOKEN = b'\x14\x94\xef\x03W=d\xf8\xf1\xa9\x18\x97\x05\x85cJyyd\rk\x82X\x13L\x00\xf5\x1c*\xf7LJ\t\xee\xca~`\x8ci\xe7%\x85A\xea\xd7\xe1\x88iM@\xc3\xb4\x07\xa1b\xe1\xf1\x9b\xddjQ6*\xaa'
AUTH_TOKEN = b'KEKEKEK'
PING_ATTEMPTS = 3
SUSTAIN_DELTA_SEC = 15

connected_hosts = []
probable_hosts = []

pp = pprint.PrettyPrinter()
sniff_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
def sniff_for_host():
    while True:
        ip_with_udp = sniff_sock.recv(65535)
        ip_info = raw_udp_ip.parse_ip_packet(ip_with_udp)
        udp_info = raw_udp_ip.parse_udp_packet(ip_info['data'])
        src_addr = (ip_info['src_ip'], udp_info['src_port'])
        dst_addr = (ip_info['dst_ip'], udp_info['dst_port'])
        if udp_info['data'] == AUTH_TOKEN:
            connected_hosts.append((src_addr, dst_addr))
        else:
            found = False
            for record in probable_hosts:
                if record[0] == (src_addr, dst_addr):
                    found = True
                    break
            if not found and not unwanted_ip(src_addr[0]):
                probable_hosts.append([(src_addr, dst_addr), PING_ATTEMPTS])
                print('QUEUED:', src_addr, dst_addr)
        print('CONNECTED:')
        pp.pprint(connected_hosts)
        print('QUEUED:')
        pp.pprint(probable_hosts)


def unwanted_ip(ip):
    return ip in ['0.0.0.0', '127.0.0.1']

def ping_probable_hosts():
    while True:
        global probable_hosts
        probable_hosts_c = probable_hosts.copy()
        for i in range(len(probable_hosts_c) - 1, -1, -1):
            record = probable_hosts_c[i]
            # attempts left
            if record[1] > 0:
                record[1] -= 1
                to_addr = record[0][0]
                from_addr = record[0][1]
                print('sending from', from_addr, 'to', to_addr)
                raw_udp_ip.send_udp(AUTH_TOKEN, from_addr, to_addr)
            else:
                del probable_hosts_c[i]
        probable_hosts = probable_hosts_c
        time.sleep(5)


def sustain_connected_hosts():
    while True:
        for to_addr, from_addr in probable_hosts.copy():
            raw_udp_ip.send_udp('ಠᴗಠ', from_addr, to_addr)
    time.sleep(SUSTAIN_DELTA_SEC)


# raw_udp_ip.send_udp('KEKEKEK', ('192.168.43.91', 443), ('192.168.43.91', 52132)) 


threading.Thread(target=sniff_for_host).start()
threading.Thread(target=ping_probable_hosts).start()
# threading.Thread(target=sustain_connected_hosts).start()