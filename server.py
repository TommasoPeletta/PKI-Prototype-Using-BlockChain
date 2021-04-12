import socket
import threading
import time
import random
import string
import rsa
import pickle
from datetime import datetime
import json
#Variables for holding information about connections
connections = []
total_connections = 0
allClient = []
blockchain=[]
currentblock = [0, 0, [], 0, [],  []]
blockUnderVer = []
invalidblockcount = []
  # [timestamp, blockid, tuple(pk, email, challange, sign), hash,id groupe consensus, singatures]
#Client class, new instance created for each connected client
#Each instance has the socket and address that is associated with items
#Along with an assigned ID and a name chosen by the client

def generateChallange(length = 20):
    letters = string.ascii_lowercase
    challange = ''.join(random.choice(letters) for i in range(length))
    return challange

def ConsensusProtocol(block):
    for i in block[4]:
        for j in allClient:
            if i == j[1]:
                strblock = json.dumps(block)
                print('sending block')
                j[2].socket.sendall(str.encode(strblock))
    global blockUnderVer
    global invalidblockcount
    blockUnderVer.append(block)
    invalidblockcount.append([block[0],[],[]])
    return 0

def VerifyBlock(block):
    #consensus group
    global blockchain
    print('verifying block')
    now = datetime.now()
    block[0] = datetime.timestamp(now)
    block[1] = blockchain[-1][1]+1
    holdhash = blockchain[-1][3]
    eligibleconsensus = []
    while 1:
        try:
            for i in allClient:
                if i[3] == 1:
                    eligibleconsensus.append(i[1])
            block[4] = random.sample(eligibleconsensus, 3)
            block[3] = rsa.compute_hash(str.encode(str([block[0],block[1],block[2],block[4],holdhash])), 'SHA-256').hex()
            break
        except:
            a = 0
    block[5] = ['0','0','0']
    ConsensusProtocol(block)  #if consensus groupe ok
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

def VerifySignCons(hashblock,pk,sign):
    hashing = rsa.verify( hashblock.encode('utf-8'),bytes.fromhex(sign), pk)
    print(hashing)
    if hashing == 'SHA-256':
        return 1
    return 0



def addAllClient(pk, email, parsed, Client):
    global currentblock
    print(pk)
    print(email)
    for i in allClient:
        if i[0] == pk and i[1] == email:
            if i[3] == 2:
                return "wait block to be validated"
            if VerifySign(parsed,pk,Client.challange):
                print('in allclient')
                Client.signal = 1
                i[2] = Client
                i[3] = 1
                return "successfully authenticated"
        elif i[0] == pk and i[1] != email:
            return "pk already in use"
            #pk already in use error
        elif i[0] != pk and i[1] == email:
            if VerifySign(parsed,pk,Client.challange):
                Client.signal = 2
                return "sign with both keys if you want to authenticate"
    #Client.pk = pk
    #Client.email = email
    #Client.signal = 1
    allClient.append([pk,email,Client,2])
    currentblock[2].append([[pk.n, pk.e], email, Client.challange, parsed[7]])
    print(currentblock)
    if len(currentblock[2]) > 2:
        Client.socket.sendall(str.encode("added to current block"))
        VerifyBlock(currentblock) #TODO make funcion concurrent
        currentblock = [0, 0, [], 0, [],  []]

    #allClient.append([pk,email,Client,0]) #TODO replace with consensus protocol
    return "authenticated new connection"



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
        global blockUnderVer
        self.socket.sendall(str.encode('challange '+self.challange))
        while self.c:
            #try:
            data = self.socket.recv(1024).decode()
            parsed = data.split()
            if len(parsed) == 1: # ask the blockchain
                if parsed[0] == b'getChain':
                    self.socket.sendall(str.encode("here is the blockchain"))
            if len(parsed) == 3: # no need to be connected make the server verify the pair
                if parsed[0] == b'verify':
                    self.socket.sendall(str.encode('pair key-email verified'))
            if len(parsed) == 5 and 0:
                if self.signal == 0: # client want to connect
                    if parsed[0] == b'pk' and parsed[2] == b'email' and parsed[4] == b'sign':
                        verifySign()
                        self.socket.sendall(str.encode("pls authenticate"))
            if len(parsed) >= 5:
                if self.signal == 0:
                    if parsed[0] == 'pk' and parsed[3] == 'email' and parsed[5] == 'chal':
                        pk = rsa.PublicKey(int(parsed[1]),int(parsed[2]))
                        ver = VerifySign(parsed,pk,self.challange)
                        if ver:
                            exit = addAllClient(pk, parsed[4], parsed, self)
                            self.socket.sendall(str.encode(exit))
                if parsed[0] == 'pk' and parsed[3] == 'email' and parsed[5] == 'sign':
                    pk = rsa.PublicKey(int(parsed[1]),int(parsed[2]))
                    "managing consensus answer"
                    for i in blockUnderVer:
                        countclient = 0
                        for c in i[4]:
                            if c == parsed[4]:
                                blockID = i[0]
                                if parsed[6] != i[3]:
                                    "say yes"
                                    verBlock = VerifySignCons(i[3],pk,parsed[6])
                                    if verBlock:
                                        ver = VerifySign(parsed,pk,parsed[6])
                                        if ver:
                                            for b in invalidblockcount:
                                                if blockID == b[0]:
                                                    b[1].append(parsed[4])
                                                    i[5][countclient] = parsed[6]
                                                    print(parsed[6])
                                                    print(len(b[1])+len(b[2]))
                                                    if len(b[1])+len(b[2]) == 3:
                                                        if len(b[1]) > len(b[2]):
                                                            blockchain.append(i)
                                                            with open('blockchain1.json', 'w') as outfile:
                                                                json.dump(blockchain, outfile,indent=1)
                                                        invalidblockcount.remove(b)
                                                        blockUnderVer.remove(i)


                                            self.socket.sendall(str.encode('valid block'))

                                else:
                                    ver = VerifySign(parsed,pk,i[3])
                                    if ver:
                                        for b in validblockcount:
                                            if blockID == b[0]:
                                                b[2].append(parsed[4])
                                        self.socket.sendall(str.encode('invalid block'))
                            countclient += 1


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
        print(blockchain)
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
    global blockchain
    #Get host and port
    host = "localhost"
    port = 1818
    with open('blockchain.json', 'r') as outfile:
        blockchain=json.load(outfile)

    for i in blockchain:
        for j in i[2]:
            pk = rsa.PublicKey(int(j[0][0]),int(j[0][1]))
            allClient.append([pk,j[1],Client(0, 0, 0, 0, 0,0 , True),0])
    print(blockchain[-1][1])
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
