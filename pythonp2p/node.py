import threading
import socket
import json
import sys
import time
import hashlib
import ipaddress
import urllib.request as req
from . import portforwardlib
from . import crypto_funcs as cf

msg_del_time = 30
PORT = 65432
FILE_PORT = 65433


class NodeConnection(threading.Thread):
    def __init__(self, main_node, sock, id, host, port):

        super(NodeConnection, self).__init__()

        self.host = host
        self.port = port
        self.main_node = main_node
        self.sock = sock
        self.terminate_flag = threading.Event()
        self.last_ping = time.time()
        # Variable for parsing the incoming json messages
        self.buffer = ""

        # The id of the connected node
        self.public_key = cf.load_key(id)
        self.id = id

        self.main_node.debug_print(
            "NodeConnection.send: Started with client ("
            + self.id
            + ") '"
            + self.host
            + ":"
            + str(self.port)
            + "'"
        )

    def send(self, data):

        try:
            data = data + "-TSN"
            self.sock.sendall(data.encode("utf-8"))

        except Exception as e:
            self.main_node.debug_print(
                "NodeConnection.send: Unexpected ercontent/ror:"
                + str(sys.exc_info()[0])
            )
            self.main_node.debug_print("Exception: " + str(e))
            self.terminate_flag.set()

    def stop(self):
        self.terminate_flag.set()

    def run(self):
        self.sock.settimeout(10.0)

        while not self.terminate_flag.is_set():
            if time.time() - self.last_ping > self.main_node.dead_time:
                self.terminate_flag.set()
                print("node" + self.id + "is dead")

            line = ""

            try:
                line = self.sock.recv(4096)

            except socket.timeout:
                # self.main_node.debug_print("NodeConnection: timeout")
                pass

            except Exception as e:
                self.terminate_flag.set()
                self.main_node.debug_print(
                    "NodeConnection: Socket has been terminated (%s)" % line
                )
                self.main_node.debug_print(e)

            if line != "":
                try:
                    # BUG: possible buffer overflow when no -TSN is found!
                    self.buffer += str(line.decode("utf-8"))

                except Exception as e:
                    print("NodeConnection: Decoding line error | " + str(e))

                # Get the messages by finding the message ending -TSN
                index = self.buffer.find("-TSN")
                while index > 0:
                    message = self.buffer[0:index]
                    self.buffer = self.buffer[index + 4 : :]

                    if message == "ping":
                        self.last_ping = time.time()
                        # self.main_node.debug_print("ping from " + self.id)
                    else:
                        self.main_node.node_message(self, message)

                    index = self.buffer.find("-TSN")

            time.sleep(0.01)

        self.main_node.node_disconnected(self)
        self.sock.settimeout(None)
        self.sock.close()
        del self.main_node.nodes_connected[self.main_node.nodes_connected.index(self)]
        time.sleep(1)


class Node(threading.Thread):
    def __init__(self, host="", port=65432):
        super(Node, self).__init__()

        self.terminate_flag = threading.Event()
        self.pinger = Pinger(self)  # start pinger
        self.delay = Delay(self) # start delay handler
        
        self.debug = False

        # a map of known streams
        self.streams = []
        # a map of viewers
        self.viewers = []
        # a pipe to talk to a child
        self.pipe = {}
        # a map of delays to peers
        self.delays = {}

        self.dead_time = (
            22  # time to disconect from node if not pinged, nodes ping after 20s
        )


        self.host = socket.gethostname()
        self.ip = req.urlopen('https://v4.ident.me').read().decode('utf8')  # own ip, will be changed by connection later
        self.port = port

        self.nodes_connected = []

        self.requested = []  # list of files we have requested.
        self.msgs = {}  # hashes of recieved messages
        self.peers = []

        self.publickey, self.private_key = cf.generate_keys()
        self.id = cf.serialize_key(self.publickey)

        self.max_peers = 10

        # accuratly get local ip
        # this is a fix to handle odd settings in /etc/hosts
        self.local_ip = portforwardlib.get_my_ip()

        self.banned = []
        portforwardlib.forwardPort(port, port, None, None, False, "TCP", 0, "", False)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.debug_print("Initialisation of the Node on port: " + str(self.port))
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(10.0)
        self.sock.listen(1)

    def debug_print(self, msg):
        if self.debug:
            print("[debug] " + str(msg))

    def network_send(self, message, exc=[]):
        for i in self.nodes_connected:
            if i.host in exc:
                pass
            else:
                i.send(json.dumps(message))

    def connect_to(self, host, port=PORT):

        if not self.check_ip_to_connect(host):
            self.debug_print("connect_to: Cannot connect!!")
            return False

        if len(self.nodes_connected) >= self.max_peers:
            self.debug_print("Peers limit reached.")
            return True

        for node in self.nodes_connected:
            if node.host == host:
                print("[connect_to]: Already connected with this node.")
                return True

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.debug_print("connecting to %s port %s" % (host, port))
            sock.connect((host, port))

            sock.send(self.id.encode("utf-8"))
            connected_node_id = sock.recv(1024).decode("utf-8")

            if self.id == connected_node_id:
                self.debug_print("Possible own ip: " + host)
                if ipaddress.ip_address(host).is_private:
                    self.local_ip = host
                else:
                    self.ip = host
                self.banned.append(host)
                sock.close()
                return False

            thread_client = self.create_new_connection(
                sock, connected_node_id, host, port
            )
            thread_client.start()
            self.nodes_connected.append(thread_client)
            self.node_connected(thread_client)

        except Exception as e:
            self.debug_print(
                "connect_to: Could not connect with node. (" + str(e) + ")"
            )

    def create_new_connection(self, connection, id, host, port):
        return NodeConnection(self, connection, id, host, port)

    def stop(self):
        self.terminate_flag.set()
        portforwardlib.forwardPort(
            self.host,
            self.port,
            None,
            None,
            True,
            "TCP",
            0,
            "PYHTON-P2P-NODE",
            True,
        )

    def run(self):
        self.pinger.start()
        self.delay.start()
        # self.fileServer.start()
        while (
            not self.terminate_flag.is_set()
        ):  # Check whether the thread needs to be closed
            try:
                connection, client_address = self.sock.accept()

                connected_node_id = connection.recv(2048).decode("utf-8")
                connection.send(self.id.encode("utf-8"))

                if self.id != connected_node_id:
                    thread_client = self.create_new_connection(
                        connection,
                        connected_node_id,
                        client_address[0],
                        client_address[1],
                    )
                    thread_client.start()

                    self.nodes_connected.append(thread_client)

                    self.node_connected(thread_client)

                else:
                    connection.close()

            except socket.timeout:
                pass

            except Exception as e:
                raise e

            time.sleep(0.01)

        self.delay.stop()
        self.pinger.stop()
        for t in self.nodes_connected:
            t.stop()

        self.sock.close()
        print("Node stopped")

    def ConnectToNodes(self):
        for i in self.peers:
            self.connect_to(i.host,PORT)
            # if not self.connect_to(i, PORT):
                #del self.peers[self.peers.index(i)]  # delete wrong / own ip from peers

    def send_message(self, data, reciever=None):
        # time that the message was sent
        if reciever:
            data = cf.encrypt(data, cf.load_key(reciever))
        self.message("msg", data, {"rnid": reciever})

    def message(self, type, data, overides={}, ex=[]):
        # time that the message was sent
        dict = {"type": type, "data": data}
        

        if "snid" not in dict:
            # sender node id
            dict["snid"] = str(self.id)

        if "sndr" not in dict:
            # sender node ip
            dict["sndr"] = self.local_ip

        if "rnid" not in dict:
            # reciever node id
            dict["rnid"] = None

        if "sig" not in dict:
            dict["sig"] = cf.sign(data, self.private_key)

        dict = {**dict, **overides}

        if "time" not in dict:
            dict["time"] = str(time.time_ns())

        self.network_send(dict, ex)

    def send_peers(self):
        self.message("peers", self.peers)

    def send_streams(self):
        self.message("strm", self.streams)

    def check_validity(self, msg):
        if not (
            "time" in msg
            and "type" in msg
            and "snid" in msg
            and "sig" in msg
            and "rnid" in msg
        ):
            return False

        if not cf.verify(msg["data"], msg["sig"], cf.load_key(msg["snid"])):
            self.debug_print(
                f"Error validating signature of message from {msg['snid']}"
            )
            return False

        if msg["type"] == "resp":
            if "ip" not in msg and "localip" not in msg:
                return False
        return True

    def check_expired(self, dta):
        sth = str(dta)
        hash_object = hashlib.md5(sth.encode("utf-8"))
        msghash = str(hash_object.hexdigest())

        # check if the message hasn't expired.
        if float(time.time()) - float(dta["time"]) < float(msg_del_time):
            if msghash not in self.msgs:
                self.msgs[msghash] = time.time()
                return False
        else:
            # if message is expired
            self.debug_print("expired:" + dta["msg"])
            return True

    def announce(self, dta, n):
        self.message(dta["type"], dta["data"], dta, ex=n)
        if len(self.msgs) > len(self.peers) * 20:
            for i in self.msgs.copy():
                if time.time() - self.msgs[i] > msg_del_time:
                    del self.msgs[i]

    def encryption_handler(self, dta):
        if dta["rnid"] == self.id:
            dta["data"] = cf.decrypt(dta["data"], self.private_key)
            return dta
        elif dta["rnid"] is None:
            return dta
        else:
            return False

    def data_handler(self, dta, n):
        now = time.time_ns()
        if not self.check_validity(dta):
            return False

        if self.check_expired(dta):
            return False
        else:
            self.announce(dta, n)

        dta = self.encryption_handler(dta)
        if not dta:
            return False

        type = dta["type"]
        data = dta["data"]
        match type:
            case "peers":
                # peers handling
                for i in data:
                    if self.check_ip_to_connect(i):
                        self.peers.append(i)

                self.debug_print("Known Peers: " + str(self.peers))
                self.ConnectToNodes()  # cpnnect to new nodes
                return True

            case "msg":
                self.on_message(data, dta["sndr"], bool(dta["rnid"]))

            case "stop":
                self.nodes_connected = [node for node in self.nodes_connected if str(node.host) != str(dta['sndr'])]


            case "strm":
                if data != []:
                    self.streams.append(data)

            case "clsd":
                self.streams.remove(data)

            case "watch":
                tup = (data[0],data[1])
                self.viewers.append(tup)
                if self.pipe['str']:
                    self.pipe['str'].send(('a',tup))
                if self.pipe['wat']:
                    self.pipe['wat'].send(('a',tup))

            case "leave":
                tup = (data[0],data[1])
                self.viewers.remove(tup)
                if self.pipe['str']:
                    self.pipe['str'].send(('r',tup))
                if self.pipe['wat']:
                    self.pipe['wat'].send(('a',tup))

            case "delay":
                if dta['init'] == self.id:
                    # measure delay
                    t0 = int(dta['t0'])
                    t1 = int(dta['t1'])
                    t2 = int(dta['time'])
                    t3 = now
                    delay = (t3-t0) - (t2-t1)
                    # do some fancy shit with this delay
                    self.delay_resp(delay, dta)
                else:
                    # the delay has been calculated and neds to be propagated
                    if "dl_rsp" in data:
                        delay = data.split(':')[1]
                        self.delays[dta['sndr']] = int(delay)
                        print(self.delays)
                        return True
                    # respond with t1 and t2
                    data = cf.encrypt("delay", cf.load_key(dta['snid']))
                    self.message("delay", data, {'init':dta['init'],
                                                'rnid':dta['snid'],
                                                 't0':dta['time'],
                                                 't1':str(now)})
            case _:
                return False
        return True


    def check_ip_to_connect(self, ip):
        if (
            ip not in self.peers
            and ip != ""
            and ip != self.ip
            and ip != self.local_ip
            and ip not in self.banned
        ):
            return True
        else:
            return False

    def on_message(self, data, sender, private):
        raise NotImplementedError

    def delay_query(self, rec):
        raise NotImplementedError

    def delay_resp(self, delay, peer):
        raise NotImplementedError

    def loadstate(self, file="state.json"):
        with open(file, "r") as f:
            peers = json.load(f)
        for i in peers:
            self.connect_to(i.host)

    def savestate(self, file="state.json"):
        with open(file, "w+") as f:
            json.dump(self.peers, f)

    def node_connected(self, node):
        self.debug_print("node_connected: " + node.id)
        if node not in self.peers:
            self.peers.append(node)
        self.send_peers()
        self.send_streams()

    def node_disconnected(self, node):
        self.debug_print("node_disconnected: " + node.id)
        if node in self.peers:
            self.peers.remove(node)

    def node_message(self, node, data):
        try:
            json.loads(data)
        except json.decoder.JSONDecodeError:
            self.debug_print(f"Error loading message from {node.host}")
            return
        self.data_handler(json.loads(data), [node.host, self.ip])


class Pinger(threading.Thread):
    def __init__(self, parent):
        self.terminate_flag = threading.Event()
        super(Pinger, self).__init__()  #Call Thread.__init__()
        self.parent = parent
        self.dead_time = 30  # time to disconect from node if not pinged

    def stop(self):
        self.terminate_flag.set()

    def run(self):
        # print("Pinger Started")
        while (
            not self.terminate_flag.is_set()
        ):  # Check whether the thread needs to be closed
            for i in self.parent.nodes_connected:
                i.send("ping")
                time.sleep(5)
        print("Pinger stopped")


class Delay(threading.Thread):
    def __init__(self, parent):
        self.terminate_flag = threading.Event()
        self.delay_flag = threading.Event()
        self.empty_delay_flag = threading.Event()
        
        super(Delay, self).__init__()  #call Thread.__init__()
        self.parent = parent

    def stop(self):
        self.terminate_flag.set()
        
    def set_delay_flag(self):
        self.delay_flag.set()

    def run(self):
        while (not self.terminate_flag.is_set()): 
            if(self.delay_flag.is_set()):
                print("Delay flag set")
                
                for i in self.parent.peers:
                    if i.host not in self.parent.delays.keys():
                        # get delay to neighbour if unknown
                        print("Delay query", i)
                        #Ping for new delays (response handled in connect.py)
                        self.parent.delay_query(i)
                
                self.delay_flag.clear()
                
        print("Delay handler stopped")