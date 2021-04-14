import socket
import threading
import time
import random
import string
import rsa
import pickle
from datetime import datetime
import json

connections = []
total_connections = 0
allClient = []
blockchain=[]
currentblock = [0, 0, [], 0, [],  []]
blockUnderVer = []
invalidblockcount = []

#generate challange of given length
def generateChallange(length = 20):
    letters = string.ascii_lowercase
    challange = ''.join(random.choice(letters) for i in range(length))
    return challange

#sending block to consensus group
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

#Adding block metadata and creating consensus group
def VerifyBlock(block):
    global blockchain
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

#verify validity of signature for authentication
def VerifySign(parsed,pk, challange):
    message = parsed[0] + ' ' + str(pk.n) + ' ' + str(pk.e) + ' ' + parsed[3] + ' ' + parsed[4] + ' ' + parsed[5] + ' ' + challange
    sign = parsed[7]
    hashing = rsa.verify( message.encode('utf-8'),bytes.fromhex(sign), pk)
    if hashing == 'SHA-256':
        return 1
    return 0

#verify validity of signature of the block's hash
def VerifySignCons(hashblock,pk,sign):
    hashing = rsa.verify( hashblock.encode('utf-8'),bytes.fromhex(sign), pk)
    if hashing == 'SHA-256':
        return 1
    return 0


# manage connection to the server and authentication
def addAllClient(pk, email, parsed, Client):
    global currentblock
    for i in allClient:
        if i[0] == pk and i[1] == email:
            if i[3] == 2:
                return "wait block to be validated"
            if VerifySign(parsed,pk,Client.challange):
                Client.signal = 1
                i[2] = Client
                i[3] = 1
                return "successfully authenticated"
        elif i[0] == pk and i[1] != email:
            return "pk already in use"
        elif i[0] != pk and i[1] == email:
            if VerifySign(parsed,pk,Client.challange):
                Client.signal = 2
                #TODO
                return "different pk: do you want to update it?"
    allClient.append([pk,email,Client,2])
    currentblock[2].append([[pk.n, pk.e], email, Client.challange, parsed[7]])
    if len(currentblock[2]) > 2:
        print("verifying block")
        VerifyBlock(currentblock)
        currentblock = [0, 0, [], 0, [],  []]
    return "added to current block"



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


    #attemps to receive msg form clients and parse them
    def run(self):
        global blockUnderVer
        self.socket.sendall(str.encode('challange '+self.challange))
        while self.c:
            try:
                data = self.socket.recv(1024).decode()
                parsed = data.split()
                if len(parsed) == 1: # ask the blockchain
                    if parsed[0] == 'getChain':
                        self.socket.sendall(str.encode("here is the blockchain"))
                if len(parsed) >= 5:
                    if self.signal == 0:
                        if parsed[0] == 'pk' and parsed[3] == 'email' and parsed[5] == 'chal': # verify authentication validity
                            pk = rsa.PublicKey(int(parsed[1]),int(parsed[2]))
                            ver = VerifySign(parsed,pk,self.challange)
                            if ver:
                                exit = addAllClient(pk, parsed[4], parsed, self)
                                self.socket.sendall(str.encode(exit))
                    if parsed[0] == 'pk' and parsed[3] == 'email' and parsed[5] == 'sign': # Verify consensus answer
                        pk = rsa.PublicKey(int(parsed[1]),int(parsed[2]))
                        for i in blockUnderVer:
                            countclient = 0
                            for c in i[4]:
                                if c == parsed[4]:
                                    blockID = i[0]
                                    if parsed[6] != i[3]:
                                        verBlock = VerifySignCons(i[3],pk,parsed[6])
                                        if verBlock:
                                            ver = VerifySign(parsed,pk,parsed[6])
                                            if ver:
                                                for b in invalidblockcount:
                                                    if blockID == b[0]:
                                                        b[1].append(parsed[4])
                                                        i[5][countclient] = parsed[6]
                                                        if len(b[1])+len(b[2]) == 3:
                                                            if len(b[1]) > len(b[2]):
                                                                blockchain.append(i)
                                                                print("adding block to the blockchain")
                                                                with open('blockchain.json', 'w') as outfile:
                                                                    json.dump(blockchain, outfile,indent=1)
                                                                for cl in allClient:
                                                                    if cl[1] == c:
                                                                        cl[2].signal = 0
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


            except Exception as e:
                print("Client " + str(self.address) + " has disconnected")
                self.socket.sendall(str.encode("You have been disconnected"))
                self.c = False
                discClient(self)
                connections.remove(self)
                print(e)
                break

#Wait for new connections
def newConnections(socket):
    while True:
        sock, address = socket.accept()
        global total_connections
        #generating new challange
        challange = generateChallange()
        connections.append(Client(sock, address, 0, 0, challange,0 , True))
        connections[len(connections) - 1].start()
        print("New connection at ID " + str(connections[len(connections) - 1]))
        total_connections += 1



#init blockchain and start the server
def main():
    global blockchain
    host = "localhost"
    port = 1818
    with open('initial_blockchain.json', 'r') as outfile:
        blockchain=json.load(outfile)

    for i in blockchain:
        for j in i[2]:
            pk = rsa.PublicKey(int(j[0][0]),int(j[0][1]))
            allClient.append([pk,j[1],Client(0, 0, 0, 0, 0,0 , True),0])
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
