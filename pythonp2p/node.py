import threading
import socket
import json
import sys
import time
import hashlib
import ipaddress
import urllib.request as req
from time import sleep
from multiprocessing import Process, Pipe
from steiner import steiner_tree, Initiator
from . import portforwardlib
from . import crypto_funcs as cf

msg_del_time = 30
PORT = 65432
STRPORT = 65433

def find_port(ip, port):
    """find an open port to receive a stream on, starting at @port"""
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(10):
        if sck.connect_ex((ip,port+i)) == 0:
            sck.close()
            return port+i
    return None


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
    def __init__(self, host="", port=PORT, strport=STRPORT):
        super(Node, self).__init__()

        self.terminate_flag = threading.Event()
        self.pinger = Pinger(self)  # start pinger
        self.delay = Delay(self) # start delay handler
        
        self.debug = False

        # a map of known streams
        self.streams = []
        # a map of viewers
        self.viewers = []
        # a collection of pipes to communicate with child processes
        self.pipe = {}
        # a map of delays to peers
        self.delays = {}

        self.dead_time = (
            22  # time to disconect from node if not pinged, nodes ping after 20s
        )


        self.host = socket.gethostname()
        self.ip = req.urlopen('https://v4.ident.me').read().decode('utf8')  # own ip, will be changed by connection later
        self.port = port
        self.strport = strport

        self.nodes_connected = []
        self.stream_connections = []

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
        portforwardlib.forwardPort(strport, strport, None, None, False, "TCP", 0, "", False)

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

    def connect_to(self, host, port=PORT, str=False):

        if not self.check_ip_to_connect(host):
            self.debug_print("connect_to: Cannot connect!!")
            return False
        # checks performed on regular connections, yolo for streams
        if not str:
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
            # regular connection to network
            if not str:
                self.nodes_connected.append(thread_client)
            # stream connection
            else:
                self.stream_connections.append(thread_client)

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
        portforwardlib.forwardPort(
            self.host,
            self.strport,
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
            # we assume lazy evaluation, if that is not the case we crash
            if ('stein' in self.pipe) and (self.pipe['stein'].poll()):
                connect = self.pipe['stein'].recv()
                # clear delays as they are no longer needed
                self.delays = {}
                self.connect_tree(connect)
                # close all connections
                # iterate tree object
                # connect to nodes

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

    def update_viewers(self):
        pass
                       
    def construct(self, init):
        """
        build a steiner tree to determine where and how to stream
        workflow
        1. measure own delay
        2. make evry1 else measure their delays
        3. collect all delays
        4. build tree
        5. broadcast tree
        6. clear delay list
        7. stop process
        8. connect accordly
        """
        # measure own delay
        iteration = self.delay.it +1
        self.delay.set_delay_flag(iteration)
        # tell peers to measure delay
        # TODO consider implications of sending this message before having our own delays measured
        self.message("steiner",self.local_ip,{'init':self.id,'it':iteration})
        # check if delays has been collected
        while len(self.delays) != len(self.peers):
            sleep(0.5)
        # transfer to global delays
        init.delays[self.local_ip] = self.delays
        # wait for response from all peers (+1 is our own)
        while len(init.delays) != len(self.peers)+1:
            if init.pipe.poll():
                peer,delay = init.pipe.recv()
                init.delays[peer] = delay
        # when all peers have responded
        tree = steiner_tree(init) # like zhiz ?
        init.pipe.send(tree)


    def build_steiner(self):
        parent, child = Pipe()
        self.pipe['stein'] = parent
        steinproc=Process(target=self.construct, args=(Initiator({},child)))
        steinproc.daemon = True
        steinproc.start()
    
    def connect_tree(self, connect: dict, sender=None):
        # disconnect from everyone but sender
        for c in self.stream_connections:
            if c.host != sender:
                c.stop()
        # connect to the new ones
        for end,path in connect.items(): 
            if ( path[0] == self.local_ip 
                 and end != self.local_ip
                 and path[1] not in [c.host for c in self.stream_connections]):
                self.connect_to(path[1], port=STRPORT, str=True)
                # the python way of [_:xs]
                connect.update({end:path[1:]})
        # pass the list to the next in line
        for c in self.stream_connections:
            if c.host != sender:
                data = cf.encrypt("",cf.load_key(c.id))
                context = {
                    'rnid':c.id,
                    'con':connect,}
                self.message("tree", data, context)


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
                self.build_steiner()

            case "addview":
                tup = (data[0],data[1])
                # if we did not watch already it was started when we were told to connect
                assert self.pipe['strm']
                self.pipe['strm'].send(('a',tup))
            # TODO: check leave
            case "leave":
                tup = (data[0],data[1])
                if tup in self.viewers:
                    self.viewers.remove(tup)
                if 'str' in self.pipe:
                    self.pipe['str'].send(('r',tup))
                self.build_steiner()

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
            case "steiner":
                # sort of long running process
                if self.delay.it < dta['it']:
                    # start delay process
                    self.delay.set_delay_flag(dta['it'])
                    self.delay.initialiser = dta['init']
                    # let unaware neighbours know we are doing this
                    self.message("steiner",data,{'init':dta['init'], 'it':dta['it']})

            case "steiner_resp":
                # was this message for me or do I need to pass it along
                if dta['init'] == self.id:
                    # A peer knows its delays
                    assert 'stein' in self.pipe # otherwise something has gone wrong
                    self.pipe['stein'].send((dta['origin'],dta['delay']))

            case "tree":
                sender = dta['sndr']
                self.viewer(dta['snid'])
                prt = find_port(self.local_ip, 6666)
                # start a stream process, presumably only to restream
                # if not self.pipe['strm']:
                #     parent,child = Pipe()
                #     self.pipe['strm'] = parent
                #     strm = stream.Stream
                data = cf.encrypt((self.local_ip, prt),cf.load_key(dta['snid']))
                self.message("addview",data,{'rnid':dta['snid']})

                connect = dta['con']
                # go do it
                self.connect_tree(connect, sender)

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
        """
        Display a message of type 'msg'
        @params data the body of the message
        @params sender ip of the sender of this message
        @params private bool indicating if this is a private message to self
        """
        print(f"{sender} says {data}")

    def delay_query(self, rec):
        """
        initiate a delay measurement
        @params rec a node in the network (an entry in peers or nodes_connected)
        """
        print("delay query")
        data = cf.encrypt("delay query",cf.load_key(rec.id))
        self.message("delay",data,{'init':self.id,'rnid':rec.id})
        print(data)
        print("delay query sent")

    def delay_resp(self, delay, peer):
        """
        gets called from data_handler
        @params delay is an int ((t3-t0)-(t2-t1)) giving the delay in nano seconds
        @params peer is the ip of the responding peer
        """
        self.delays[peer['sndr']] = delay
        print("self.delays", self.delays)
        
        #Send delay to our neighbour
        data = cf.encrypt(f'dl_rsp:{delay}', cf.load_key(peer['snid']))
        self.message("delay",data,{'rnid':peer['snid'], 'init':self.id})
    
    def viewer(self, rec, strm):
        """Tell a streamer that self wants to watch"""
        port = find_port(self.local_ip, strm.port)
        if port:
            strm.port = port
            """
            build steiner tree
            1. tell streamer to build steiner tree
            2. connect to stream
            """
            data = cf.encrypt((self.local_ip,port), cf.load_key(rec))
            self.message("addviewer", data, {'rnid':rec})
        else:
            raise OSError(98)

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
        self.it = 0
        self.initialiser = None
        
        super(Delay, self).__init__()  #call Thread.__init__()
        self.parent = parent

    def stop(self):
        self.terminate_flag.set()
        
    def set_delay_flag(self, it):
        self.it = it
        self.delay_flag.set()

    def run(self):
        while (not self.terminate_flag.is_set()):
            if(self.delay_flag.is_set()):
                print("Delay flag set")
                
                for i in self.parent.nodes_connected:
                    if i.host not in self.parent.delays:
                        # get delay to neighbour if unknown
                        print("Delay query", i)
                        #Ping for new delays (response handled in connect.py)
                        self.parent.delay_query(i)
                if self.initialiser:
                    # broadcast
                    context = { 'init':self.initialiser,
                                'delay':self.parent.delays,
                                 'it':self.it,
                                 'origin':self.parent.local_ip }
                    self.parent.message("steiner_resp","",context)
                    # the delays has been sent, we dont need it anymore
                    self.parent.delays = {}
                self.delay_flag.clear()
                
        print("Delay handler stopped")