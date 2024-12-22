import base64
import json
import os
import sys
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import ssl
from scapy.all import *

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

class GreeSrv:
    def __init__(self, ip, port, hostname, tls):
        if not ip or not port or not hostname:
            print('* IP, Port and Hostname need to be set!')
            exit(1)
        self.ip = ip
        self.port = port
        self.hostname = hostname
        self.tls = eval(tls)
        self.srv = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)#SOCK_DGRAM)
        self.cmd = self.Cmd(self.ip, self.port, self.hostname)
        self.instruct()
        self.serve()

    def instruct(self):
       print('******************************************************')
       print('If this is a first run then follow this procedure: ')
       print('1. Turn off the HVAC unit                          ')
       print('2. Override the \'dis.gree.com\' DNS A record via your DNS server to point to {}'.format(self.ip))
       print('   Note: While it shouldn\'t be necessary, you could also set a static ip leasing for the HVAC unit and block ALL connections coming from it,')
       print('         except for destinations: this server and the dns server')
       print('3. Reset the HVAC unit\'s WiFi unit (MODE + WIFI) and wait around ~2 minutes')
       print('4. Once the HVAC unit\'s WiFI SSID shows up connect to it from a device capable of running Python3!')
       print('     HVAC\'s WiFi SSID: last bits of its MAC address')
       print('     HVAC\'s WiFi password: \'12345678\'')
       print('5. Run \'python3 register.py\'')
       print('If all goes well, this server should shortly receive requests :)') 
       print('******************************************************')
       print()

    def serve(self):
        print(f'{self.ip}, {self.port}')
        self.srv.bind((self.ip, self.port))
        self.srv.listen()
        print('* Server is running on (tcp) {}:{}, DNS A record: {}'.format(self.ip, self.port, self.hostname))

        while True:
            conn, address = self.srv.accept()
            client_handler = threading.Thread(target=self.handle_client, args=(conn, address))
            client_handler.start()

    def handle_client(self, conn, address):
        if self.tls is True:
            print(f"SSL handshake started with client: {address}")
            conn = self.handle_handshake_tls(conn)
            print(f"SSL handshake ended with client: {address}")

        with conn:
            keep_alive = True
            while keep_alive:
                message = conn.recv(1024)
                keep_alive, response = self.cmd.process(message)
                conn.sendall(response)

    class Cmd:
        def __init__(self, ip, port, hostname):
            self.init_cipher()
            self.ip = ip
            self.port = port
            self.hostname = hostname

        def init_cipher(self):
            key = 'a3K8Bx%2r8Y7#xDh'
            self.cipher = Cipher(algorithms.AES(key.encode('utf-8')), modes.ECB(), backend=default_backend())

        def decrypt(self, pack_encoded):
            decryptor = self.cipher.decryptor()
            pack_decoded = base64.b64decode(pack_encoded)
            pack_decrypted = decryptor.update(pack_decoded) + decryptor.finalize()
            pack_unpadded = pack_decrypted[0:pack_decrypted.rfind(b'}') + 1]
            return pack_unpadded.decode('utf-8')

        def encrypt(self, pack):
            def add_pkcs7_padding(data):
                length = 16 - (len(data) % 16)
                padded = data + chr(length) * length
                return padded

            encryptor = self.cipher.encryptor()
            pack_padded = add_pkcs7_padding(pack)
            pack_encrypted = encryptor.update(bytes(pack_padded, encoding='utf-8')) + encryptor.finalize()
            pack_encoded = base64.b64encode(pack_encrypted)
            return pack_encoded.decode('utf-8')

        def finalize(fn):
            def runner(*args, **kwargs):
                keepalive, results = fn(*args, **kwargs)
                results = json.dumps(results).encode()
                return keepalive, results
            return runner

        @finalize
        def cmd_dis(self, msg):
            print('    Discovery request')
            pack = {'t': 'svr',
                      'ip': self.ip,
                      'ip2': self.ip,
                      'Ip3': self.ip,
                      'host': self.hostname,
                      'udpPort': self.port,
                      'tcpPort': self.port,
                      'protocol': 'TCP',
                      'datHost': self.hostname,
                      'datHostPort': self.port}

            answer = {'t': 'pack',
                      'i': 1,
                      'uid': 0,
                      'cid': '',
                      'tcid': msg['mac'],
                      'pack': self.encrypt(json.dumps(pack))}

            return False, answer

        @finalize
        def cmd_devLogin(self, msg):
            print('    DevLogin request')
            norm_arr = [8, 9, 14, 15, 2, 3, 10, 11, 4, 5, 0, 1]
            cid = ''.join([msg['mac'][c] for c in norm_arr])

            pack = {'t': 'loginRes',
                    'r': 200,
                    'cid': cid,
                    'uid': 0}

            answer = {'t': 'pack',
                      'i': 1,
                      'uid': 0,
                      'cid': '',
                      'tcid': '',
                      'pack': self.encrypt(json.dumps(pack))}

            return True, answer

        @finalize
        def cmd_tm(self):
            print('    Tm request')
            time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            answer = {'t': 'tm',
                      'time': time}
            return True, answer

        @finalize
        def cmd_hb(self):
            print('    Hb request')
            answer = {'t': 'hbok'}
            return True, answer

        def cmd_pack(self, msg):
            print('    Pack request, recursing')
            msg = self.decrypt(msg['pack'])
            return self.process(msg)

        def process(self, msg):
            try:
                msg = json.loads(msg)
                print('  Received: {}'.format(msg))
                cmd = msg['t']
                if cmd == 'dis':
                    return self.cmd_dis(msg)
                if cmd == 'devLogin':
                    return self.cmd_devLogin(msg)
                if cmd == 'tm':
                    return self.cmd_tm()
                if cmd == 'hb':
                    return self.cmd_hb()
                if cmd == 'pack':
                    return self.cmd_pack(msg)
                return False, b''

            except Exception as E:
                    print('* Exception: {} on message {}'.format(str(E), str(msg)))
                    return False, b''
    def handle_handshake_tls(self, conn):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certfile='server.crt', keyfile='server.key')

        # Set cipher suites to include a broader range
        server_context.set_ciphers("ALL:@SECLEVEL=1")  # Adjust security level if needed

        ssl_client_conn = server_context.wrap_socket(conn, server_side=True)
        return ssl_client_conn


host_input = os.getenv("SERVER_HOST", "127.0.0.1")
port_input = int(os.getenv("SERVER_PORT", "1813"))
hostname_input = os.getenv("SERVER_DOMAIN", "eu.dis.gree.com")
tls_input = os.getenv("TLS", "False")
####
print('******************************************************')
print(f"Host: {host_input}")
print(f"Port: {port_input}")
print(f"Hostname: {hostname_input}")
print(f"TLS: {tls_input}")
print('******************************************************')

GreeSrv(host_input, port_input, hostname_input, tls_input)

