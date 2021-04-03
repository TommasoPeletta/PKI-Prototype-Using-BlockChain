import socket
import threading
import sys
import rsa
import pickle
import hashlib

#Wait for incoming data from server
#.decode is used to turn the message in bytes to a string
challange = ''
def receive(socket, signal):
    global challange
    while signal:
        try:
            data = socket.recv(32).decode()
            parsed = data.split()
            if parsed[0] == 'challange':
                challange = parsed[1]
                print('received challange ' + challange)
            else:
                print(data)
        except:
            print("You have been disconnected from the server")
            signal = False
            break

#Get host and port
host = "localhost"
port = 1818
challange = ''
#Attempt connection to server
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
except:
    print("Could not make a connection to the server")
    input("Press enter to quit")
    sys.exit(0)

#Create new thread to wait for data
receiveThread = threading.Thread(target = receive, args = (sock, True))
receiveThread.start()

#Send data to server
#str.encode is used to turn the string message into bytes so it can be sent across the network
pubkey = ''
privkey = ''
email = 'tom'
while True:
    message = input()
    if message == "disconnect":
        sock.close()
        break
    elif message == "generate key":
        (pubkey, privkey) = rsa.newkeys(1024)
        print(pubkey,privkey)
    elif message == "set email":
        email = input()
    elif message == "connect":
        strpubkey = str(pubkey.n) + ' ' + str(pubkey.e)
        verify = 'pk ' + strpubkey + ' ' + 'email ' + email + ' ' + 'sign ' + challange
        signature = rsa.sign(verify.encode('utf-8'), privkey,'SHA-256').hex()
        verify = verify + ' ' + signature
        sock.sendall(str.encode(verify))
        print('sending signed pk email')
    else:
        print('hello')
