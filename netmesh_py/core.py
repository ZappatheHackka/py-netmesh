import uuid, json, threading, socket, queue, datetime, time

class Node:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.node_id = uuid.uuid4()
        self.listen_thread = None
        self.discovery_thread = None
        self.process_thread = None
        self.stop_event = threading.Event()
        self.neighbors = {}
        self.seen_messages = []
        self.packet_queue = queue.Queue()
        self.message_json = {
            "type": "TEXT",
            "origin": "netmesh_py",
            "node_id": str(self.node_id),
            "ip": self.ip,
            "port": self.port,
            "payload": {
                "message": "KLAUS HAAS"
            }
        }

    def start(self):
        self.listen_thread = threading.Thread(target=self.listener_loop)
        self.listen_thread.start()

        self.discovery_thread = threading.Thread(target=self.discovery_loop)
        self.discovery_thread.start()

        self.processor_thread = threading.Thread(target=self.processor)
        self.processor_thread.start()

    def listener_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", self.port))
        print("Listening thread now active...")
        while True:
            data, addr = sock.recvfrom(1024)
            try:
                message = json.loads(data.decode('utf-8'))
                message["ip"] = addr[0]
                message["port"] = addr[1]
                print("Received message: ", message, " from ", addr, ". Adding to queue...\n")
                self.packet_queue.put(message)
            except json.decoder.JSONDecodeError:
                print("Received message not in expected format. Ignoring...\n")

    #TODO: Add sending custom messages
    def discovery_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peers = [50000, 50001]
        while True:
            for p in peers:
                if p != self.port:
                    sock.sendto(json.dumps(self.message_json).encode('utf-8'), ('127.0.0.1', p))
            time.sleep(3)

    def processor(self):
        print("Processor thread now active...")
        while True:
            message = self.packet_queue.get()
            try:
                if message["origin"]:
                    if message["origin"] == "netmesh_py":
                        if message['node_id'] == str(self.node_id):
                            continue
                        elif message['node_id'] in self.neighbors:
                            print("Node ", message["node_id"], " has already been discovered.\n")
                            time = datetime.datetime.now()
                            self.neighbors[message["node_id"]]["last_seen"] = time
                            self.seen_messages.append(message)
                        else:
                            print("Node ", message["node_id"], " has not been discovered. Adding ", message["node_id"],
                                  " to neighbors list.\n")
                            time = datetime.datetime.now()
                            self.neighbors[message["node_id"]] = {
                                "ip": message["ip"],
                                "port": message["port"],
                                "last_seen": time
                            }
                            self.seen_messages.append(message)
                    else:
                        print("'origin' key is designates this message is foreign. Ignoring...\n")
            except KeyError:
                print("Message does not contain a 'origin' key. Ignoring...\n")

    def stop(self):
        print("Stopping node...")
        self.stop_event.set()
        self.listen_thread.join()
        self.discovery_thread.join()
        self.processor_thread.join()
        print("Node stopped cleanly.")