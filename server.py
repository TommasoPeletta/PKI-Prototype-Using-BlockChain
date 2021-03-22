import socket
import threading
import time
#Variables for holding information about connections
connections = []
total_connections = 0
allClient = []
#Client class, new instance created for each connected client
#Each instance has the socket and address that is associated with items
#Along with an assigned ID and a name chosen by the client

def VerifyPk(pk, Client):
    return addAllClient(pk, Client)
    #time.sleep(10)

def addAllClient(pk, Client):
    for i in allClient:
        if i[0] == pk:
            i[1] = Client
            i[2] = 1
            return "not first time"
    allClient.append([pk, Client, 1])
    Client.pk = pk
    return "first time"

def discClient(Client):
    for i in allClient:
        if i[0] == Client.pk:
            i[2] = 0

class Client(threading.Thread):
    def __init__(self, socket, address, pk, signal):
        threading.Thread.__init__(self)
        self.socket = socket
        self.address = address
        self.pk = pk
        self.signal = signal

    def __str__(self):
        return str(self.pk) + " " + str(self.address)

    #Attempt to get data from client
    #If unable to, assume client has disconnected and remove him from server data
    #If able to and we get data back, print it in the server and send it back to every
    #client aside from the client that has sent it
    #.decode is used to convert the byte data into a printable string

    def run(self):
        self.socket.sendall(str.encode("waiting for signed pk"))
        while self.signal:
            try:
                data = self.socket.recv(32)
                parsed = data.split()
                if len(parsed) > 1:
                    if parsed[0] == b'pk':
                        ver = VerifyPk(parsed[1], self)
                        self.socket.sendall(str.encode(ver))
            except Exception as e:
                print("Client " + str(self.address) + " has disconnected")
                self.signal = False
                discClient(self)
                connections.remove(self)
                print(e)
                break

#Wait for new connections
def newConnections(socket):
    while True:
        sock, address = socket.accept()
        global total_connections
        connections.append(Client(sock, address, 0, True))
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
