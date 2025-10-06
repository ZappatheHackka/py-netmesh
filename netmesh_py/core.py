import uuid, json, threading, socket, queue, datetime, time

class Node:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.node_id = uuid.uuid4()
        self.neighbors = {}
        self.seen_messages = []
        self.packet_queue = queue.Queue()
        self.message_json = {
            "type": "TEXT",
            "origin": "netmesh_py",
            "node_id": self.node_id,
            "ip": self.ip,
            "port": self.port,
            "payload": {
                "message": "KLAUS HAAS"
            }
        }

    def start(self):
        listen_thread = threading.Thread(target=self.listener_loop)
        listen_thread.start()

        discovery_thread = threading.Thread(target=self.discovery_loop)
        discovery_thread.start()

        processor_thread = threading.Thread(target=self.processor)
        processor_thread.start()

    def listener_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.ip, self.port))
        while True:
            data, addr = sock.recvfrom(1024)
            try:
                message = json.loads(data.decode('utf-8'))
                print("Received message: ", message, " from ", addr, ". Adding to queue...\n")
                self.packet_queue.put(message)
            except json.decoder.JSONDecodeError:
                print("Received message not in expected format. Ignoring...\n")

    #TODO: Add sending custom messages
    def discovery_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            sock.sendto(json.dumps(self.message_json).encode('utf-8'), ('255.255.255.255', self.port))
            time.sleep(3)

    def processor(self):
        while True:
            message = self.packet_queue.get()
            try:
                if message["origin"]:
                    if message["origin"] == "netmesh_py":
                        if message['node_id'] in self.neighbors:
                            print("Node ", message["node_id"], " has already been discovered.\n")
                            time = datetime.datetime.now()
                            self.neighbors[message["node_id"]]["last_seen"] = time
                            self.seen_messages.append(message)
                        else:
                            print("Node ", message["node_id"], " has not been discovered. Adding ", message["node_id"],
                                  " to neighbors list.\n")
                            time = datetime.datetime.now()
                            self.neighbors[message["node_id"]] = {
                                "ip": self.ip,
                                "port": self.port,
                                "last_seen": time
                            }
                            self.seen_messages.append(message)
                    else:
                        print("'origin' key is designates this message is foreign. Ignoring...\n")
            except KeyError:
                print("Message does not contain a 'origin' key. Ignoring...\n")