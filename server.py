import socket
import threading
import time
import random
import string
import rsa
import pickle

#Variables for holding information about connections
connections = []
total_connections = 0
allClient = []
#Client class, new instance created for each connected client
#Each instance has the socket and address that is associated with items
#Along with an assigned ID and a name chosen by the client


def generateChallange(length = 20):
    letters = string.ascii_lowercase
    challange = ''.join(random.choice(letters) for i in range(length))
    return challange

def VerifyPk(pk, email, sign, Client):
    #consensus group
    return 1
    #time.sleep(10)


def VerifySign(parsed,pk, challange):
    message = parsed[0] + ' ' + str(pk.n) + ' ' + str(pk.e) + ' ' + parsed[3] + ' ' + parsed[4] + ' ' + parsed[5] + ' ' + challange
    sign = parsed[7]
    hashing = rsa.verify( message.encode('utf-8'),bytes.fromhex(sign), pk)
    print(hashing)
    if hashing == 'SHA-256':
        return 1
    return 0



def addAllClient(pk, email, Client):
    for i in allClient:
        if i[0] == pk and i[1] == email:
            Client.signal = 1
            i[2] = Client
            i[3] = 1
            return "successfully authenticated"
        elif i[0] == pk and i[1] != email:
            return "pk already in use"
            #pk already in use error
        elif i[0] != pk and i[1] == email:
            Client.signal = 2
            return "sign your last message if you want to update your pk"
    #Client.pk = pk
    #Client.email = email
    #Client.signal = 1
    allClient.append([pk,email,Client,1]) #TODO replace with consensus protocol
    return "authenticated new connection"
'''
            Client.pk = pk
            Client.email = email
            allClient.append([pk, email, Client, 1])
'''


def discClient(Client):
    for i in allClient:
        if i[1] == Client.email and i[0] == Client.pk:
            i[2] = 0
            Client.signal = 0

class Client(threading.Thread):
    def __init__(self, socket, address, pk, email,challange, signal,c):
        threading.Thread.__init__(self)
        self.socket = socket
        self.address = address
        self.pk = pk
        self.email = email
        self.challange = challange
        self.signal = signal
        self.c = c

    def __str__(self):
        return str(self.pk) + " " + str(self.address)

    #Attempt to get data from client
    #If unable to, assume client has disconnected and remove him from server data
    #If able to and we get data back, print it in the server and send it back to every
    #client aside from the client that has sent it
    #.decode is used to convert the byte data into a printable string

    def run(self):
        self.socket.sendall(str.encode('challange '+self.challange))
        while self.c:
            #try:
            data = self.socket.recv(1024).decode()
            parsed = data.split()
            if len(parsed) == 1: # ask the blockchain
                if parsed[0] == b'getChain':
                    self.socket.sendall(str.encode("here is the blockchian"))
            if len(parsed) == 3: # no need to be connected make the server verify the pair
                if parsed[0] == b'verify':
                    self.socket.sendall(str.encode('pair key-email verified'))
            if len(parsed) == 5 and 0:
                if self.signal == 0: # client want to connect
                    if parsed[0] == b'pk' and parsed[2] == b'email' and parsed[4] == b'sign':
                        verifySign()
                        self.socket.sendall(str.encode("pls authenticate"))
            if len(parsed) >= 5 and self.signal == 0:
                if parsed[0] == 'pk' and parsed[3] == 'email' and parsed[5] == 'sign':
                    pk = rsa.PublicKey(int(parsed[1]),int(parsed[2]))
                    ver = VerifySign(parsed,pk,self.challange)
                    if ver:
                        exit = addAllClient(pk, parsed[3], self)
                        self.socket.sendall(str.encode(exit))

                        '''
                        if self.signal == 1:#
                            ver = VerifyPk(parsed[1], parsed[3], parsed[5],self)
                            self.socket.sendall(str.encode("connected"))
                        if self.signal == 2: # client want to update pk
                            ver = VerifyPk(parsed[1], parsed[3], parsed[5],self)
                            self.socket.sendall(str.encode("send new pk and sign"))
                        if self.signal == 3: # client want to save new pk
                            ver = VerifyPk(parsed[1], parsed[3], parsed[5],self)
                            self.socket.sendall(str.encode("want to save new pair pk email?"))
                            '''
'''
            except Exception as e:
                print("Client " + str(self.address) + " has disconnected")
                self.socket.sendall(str.encode("You have been disconnected"))
                self.c = False
                discClient(self)
                connections.remove(self)
                print(e)
                break
'''
#Wait for new connections
def newConnections(socket):
    while True:
        sock, address = socket.accept()
        global total_connections
        challange = generateChallange()
        connections.append(Client(sock, address, 0, 0, challange,0 , True))
        connections[len(connections) - 1].start()
        print("New connection at ID " + str(connections[len(connections) - 1]))
        total_connections += 1


def listenServer(newConnectionsThread):
    while 1:
        message = input()
        if message == "connection":
            print(connections[0].socket)
            print(connections[0].address)
            print(connections[0].pk)
            print(connections[0].email)
            print(connections[0].signal)



def main():
    #Get host and port
    host = "localhost"
    port = 1818

    #Create new server socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)

    #Create new thread to wait for connections
    newConnectionsThread = threading.Thread(target = newConnections, args = (sock,))
    Serverlisten = threading.Thread(target = listenServer, args = (sock, ))
    newConnectionsThread.start()
    Serverlisten.start()

main()
