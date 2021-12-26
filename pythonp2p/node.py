import threading
import uuid
import socket
import json
import pickle
import sys
import time
import random
import hashlib
from . import data_request_management as dtrm
from .file_transfer import FileDownloader, fileServer
from . import portforwardlib

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
        self.id = id

        try:
            uuid.UUID(str(self.id))
        except ValueError:
            self.stop()
            return False

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
    def __init__(self, host="", port=65432, file_port=65433):

        self.terminate_flag = threading.Event()

        self.pinger = Pinger(self)  # start pinger
        self.fileServer = fileServer(self, file_port)

        super(Node, self).__init__()  # CAll Thread.__init__()

        self.debug = True

        self.dead_time = (
            30  # time to disconect from node if not pinged, nodes ping after 20s
        )

        self.host = host
        self.ip = host  # own ip, will be changed by connection later
        self.port = port
        self.file_port = file_port

        self.nodes_connected = []

        self.requested = []  # list of files we have requested.
        self.msgs = {}  # hashes of recieved messages
        self.peers = []

        self.id = str(uuid.uuid4())

        self.max_peers = 10

        hostname = socket.gethostname()

        self.local_ip = socket.gethostbyname(hostname)

        portforwardlib.forwardPort(port, port, None, None, False, "TCP", 0, "", True)
        portforwardlib.forwardPort(
            file_port, file_port, None, None, False, "TCP", 0, "", True
        )

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print(
            "Initialisation of the Node on port: "
            + str(self.port)
            + " on node ("
            + self.id
            + ")"
        )
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

        if host == self.ip or host == "" or host == self.local_ip:
            self.debug_print("connect_to: Cannot connect with yourself!!")
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
            connected_node_id = str(sock.recv(128).decode("utf-8"))

            if self.id == connected_node_id:
                self.debug_print("own ip: " + host)
                self.ip = (
                    host  # set our own ip - this canbug if two nodes have the same id
                )
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
        portforwardlib.forwardPort(
            self.host,
            self.file_port,
            None,
            None,
            True,
            "TCP",
            0,
            "PYHTON-P2P-FILESERVER",
            True,
        )

    def run(self):
        self.pinger.start()
        self.fileServer.start()
        while (
            not self.terminate_flag.is_set()
        ):  # Check whether the thread needs to be closed
            try:
                connection, client_address = self.sock.accept()

                connected_node_id = str(connection.recv(128).decode("utf-8"))
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

        self.pinger.stop()
        self.fileServer.stop()
        for t in self.nodes_connected:
            t.stop()

        time.sleep(0.5)
        self.pinger.join()
        self.fileServer.join()
        for t in self.nodes_connected:
            t.join()

        self.sock.close()
        print("Node stopped")

    def ConnectToNodes(self):
        for i in self.peers:
            if not self.connect_to(i, PORT):
                del self.peers[self.peers.index(i)]  # delete wrong / own ip from peers

    def send_message(self, data):
        # time that the message was sent
        self.message("msg", data)

    def message(self, type, data, overides={}, ex=[]):
        # time that the message was sent
        dict = {"type": type, "data": data}
        if "time" not in dict:
            dict["time"] = str(time.time())

        if "snid" not in dict:
            # sender node id
            dict["snid"] = str(self.id)

        dict = {**dict, **overides}
        self.network_send(dict, ex)

    def send_peers(self):
        self.message("peers", self.peers)

    def check_validity(self, msg):
        if "time" in msg and "type" in msg and "snid" in msg:
            return True

        if msg["type"] == "resp":
            if "ip" not in msg and "localip" not in msg:
                return False
        return False

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

    def data_handler(self, dta, n):
        if not self.check_validity(dta):
            return False

        if self.check_expired(dta):
            return False
        else:
            self.announce(dta, n)

        type = dta["type"]
        data = dta["data"]

        if type == "peers":
            # peers handling
            for i in data:
                if i not in self.peers and i != "" and i != self.ip:
                    self.peers.append(i)

            self.debug_print("Known Peers: " + str(self.peers))
            self.ConnectToNodes()  # cpnnect to new nodes
            return True

        if type == "msg":
            self.debug_print("Incomig Message: " + data)

        if type == "req":
            if dtrm.have_file(data):
                self.message(
                    "resp",
                    data,
                    {"ip": self.ip, "localip": self.local_ip},
                )
                self.debug_print(
                    "recieved request for file: " + data + " and we have it."
                )
            else:
                self.debug_print(
                    "recieved request for file: " + data + " but we do not have it."
                )

        if type == "resp":
            self.debug_print("node: " + dta["snid"] + " has file " + data)
            if data in self.requested:
                print("node " + dta["snid"] + " has our file!")
                if dta["ip"] == "":
                    if dta["localip"] != "":
                        ip = dta["localip"]
                else:
                    ip = dta["ip"]

                downloader = FileDownloader(
                    ip, FILE_PORT, str(data), self.fileServer.dirname
                )
                downloader.start()
                downloader.join()

    def requestFile(self, fhash):
        if fhash not in self.requested and fhash not in dtrm.getallfiles():
            self.requested.append(fhash)
            self.message("req", fhash)

    def addfile(self, path):
        s = dtrm.addfile(path)
        dtrm.refresh()
        return s

    def setfiledir(self, path):
        self.fileServer.dirname = path
        self.dtrm.download_path = path

    def node_connected(self, node):
        self.debug_print("node_connected: " + node.id)
        if node.host not in self.peers:
            self.peers.append(node.host)
        self.send_peers()

    def node_disconnected(self, node):
        self.debug_print("node_disconnected: " + node.id)
        if node.host in self.peers:
            self.peers.remove(node.host)

    def node_message(self, node, data):
        try:
            json.loads(data)
        except json.decoder.JSONDecodeError:
            self.debug_print(f"Error loading message from {node.id}")
            return
        self.data_handler(json.loads(data), [node.host, self.ip])


class Pinger(threading.Thread):
    def __init__(self, parent):
        self.terminate_flag = threading.Event()
        super(Pinger, self).__init__()  # CAll Thread.__init__()
        self.parent = parent
        self.dead_time = 30  # time to disconect from node if not pinged

    def stop(self):
        self.terminate_flag.set()

    def run(self):
        print("Pinger Started")
        while (
            not self.terminate_flag.is_set()
        ):  # Check whether the thread needs to be closed
            for i in self.parent.nodes_connected:
                i.send("ping")
                time.sleep(20)
        print("Pinger stopped")
