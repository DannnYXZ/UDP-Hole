import socket

def get(sock, q):
    sock.send(
        bytes('GET '+q+' HTTP/1.1\r\n' +
        'Host: secret-tundra-73822.herokuapp.com\r\n' +
        'Connection: Keep-Alive\r\n' +
        'Keep-Alive: timeout=1000, max=1000\r\n' +
        '\r\n',
        'UTF-8')
    )


def send_id(sock, id):
    sock.send(bytes('ID ' + id, 'utf-8'))

PORT = 5000
PORT = 80
SERVER = '127.0.0.1'
SERVER = 'secret-tundra-73822.herokuapp.com'
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print(sock.connect((SERVER, PORT)))
print('connected')
get(sock, '/getaddr')
print(sock.recv(1024))
input()
get(sock, '/echo')
print(sock.recv(1024))
id = input('ID: ')
send_id(sock, id)
# send_id('KEK')
# print(sock.recv(1024))
input()
