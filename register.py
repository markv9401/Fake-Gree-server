import json
import socket
import sys

if len(sys.argv) != 3:
    print('Usage: python3 {} <WiFi SSID> <WiFi password>'.format(sys.argv[0]))
    exit(1)

msg = {'psw': sys.argv[2],
       'ssid': sys.argv[1],
       't': 'wlan'}

expected = {'t': 'ret',
            'r': 200}

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    s.connect(('192.168.1.1', 7000))
    s.send(json.dumps(msg).encode())
    msg = s.recv(1024)
    msg = json.loads(msg)
    if msg == expected:
        print('Successfully sent WiFi connection details to HVAC unit. The Fake Gree server should shortly start seeing connections!')
    else:
        print('ERROR: {}'.format(str(msg)))
except ConnectionRefusedError:
        print('ERROR: cannot contact HVAC unit. Are you connected to its WiFi?')
        exit(1)
except json.decoder.JSONDecodeError:
        print('ERROR: response is not valid JSON: {}'.format(msg))
except Exception as E:
        print('ERROR: {}'.format(str(E)))
        exit(1)
