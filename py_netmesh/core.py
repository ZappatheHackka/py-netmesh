import uuid, json, threading, socket, queue, datetime, time, logging
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

class Node:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.node_id = uuid.uuid4()
        self.alias = None
        self.listen_thread = None
        self.discovery_thread = None
        self.process_thread = None
        self.stop_event = threading.Event()
        self.allowed_neighbors = []
        self.routing_table = {}
        self.routes_to_send = {}
        self.captured_packets = []
        self.message_payloads = []
        self.packet_queue = queue.Queue()
        self.message_json = {
            "type": "PROBE",
            "origin": "py_netmesh",
            "alias": None,
            "node_id": str(self.node_id),
            "ip": self.ip,
            "port": self.port,
            "payload": {
                "message": "KLAUS HAAS"
            },
            "routing_table": self.routes_to_send,
        }

    def start(self):
        alias = input("Enter an alias for your node: ").strip()
        self.alias = alias
        self.message_json["alias"] = self.alias

        self.listen_thread = threading.Thread(target=self.listener_loop, daemon=True)
        self.listen_thread.start()

        self.discovery_thread = threading.Thread(target=self.discovery_loop, daemon=True)
        self.discovery_thread.start()

        self.processor_thread = threading.Thread(target=self.processor, daemon=True)
        self.processor_thread.start()

        self.user_interface()

    def listener_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", self.port))
        print("Listening thread now active...")
        while True:
            data, addr = sock.recvfrom(1024)
            # print(f"[{self.port}] Received packet from {addr}")
            try:
                message = json.loads(data.decode('utf-8'))
                message["ip"] = addr[0]
                if message["alias"] == self.alias:
                    continue
                else:
                    self.packet_queue.put(message)
            except json.decoder.JSONDecodeError:
                continue


    def discovery_loop(self):
        # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # print("Discovery thread now active...")
        # while True:
        #     sock.sendto(json.dumps(self.message_json).encode('utf-8'), ('<broadcast>', self.port))
        #     time.sleep(5)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # For virtual testing
        while not self.stop_event.is_set():
            for neighbor_port in self.allowed_neighbors:
                # print(f"[{self.port}] Sending discovery to {neighbor_port}")
                sock.sendto(json.dumps(self.message_json).encode('utf-8'),
                            ('127.0.0.1', neighbor_port))
            time.sleep(5)

    def processor(self):
        print("Processor thread now active...")
        while True:
            message = self.packet_queue.get()
            try:
                if message["origin"] == "py_netmesh":
                    if message["type"] == "CHAT":
                        if message["destination_id"] == str(self.node_id):
                            print(f"DIRECT MESSAGE FROM {message['alias']}:", message['payload']['message'])
                        else:
                            #flood algo, route to next best node
                            pass
                    elif message["type"] == "PROBE":
                        if message["port"] not in self.allowed_neighbors: #converting port to str because taking
                            continue                                               #input from cli converts int to str
                        else:
                            if str(message['node_id']) == str(self.node_id):
                                continue
                            elif message['node_id'] in self.routing_table:
                                time = datetime.datetime.now()
                                self.routing_table[message["node_id"]]["last_seen"] = time
                                self.captured_packets.append(message)
                                self.message_payloads.append(message)
                            else:
                                print(f"New Node found: {message['node_id']} AKA {message['alias']}.")
                                time = datetime.datetime.now()
                                self.routing_table[message["node_id"]] = {
                                    "ip": message["ip"],
                                    "port": message["port"],
                                    "alias": message["alias"],
                                    "hop_count": 1,
                                    "next_hop": None,
                                    "last_seen": time
                                }
                                self.routes_to_send[message["node_id"]] = {
                                    "alias": message["alias"],
                                    "hop_count": 1,
                                }
                                self.scan_for_routes(routes=message["routing_table"])
                                self.captured_packets.append(message)
                                self.message_payloads.append(message)
                else:
                    print("'origin' key is designates this message is foreign. Ignoring...\n")
            except KeyError as e:
                if e == "origin":
                    pass # packet not of our mesh, do nothing
                else:
                    print("KeyError:", e)

    def stop(self):
        print("Stopping node...")
        self.stop_event.set()
        self.listen_thread.join()
        self.discovery_thread.join()
        self.processor_thread.join()
        print("Node stopped cleanly.")

    def send_message(self, recipient_alias: str, message: str):
        message = {
            "type": "CHAT",
            "alias": self.alias,
            "recipient": recipient_alias,
            "destination_id": None,
            "origin": "py_netmesh",
            "node_id": str(self.node_id),
            "ip": self.ip,
            "payload": {
                "message": message.strip()
            }
        }

        recipient_node = None

        for node_id, info in self.routing_table.items():
            if info.get("alias") == recipient_alias:
                recipient_node = info
                break

        if recipient_node:
            print("Recipient node found!")
            message["destination_id"] = recipient_node["node_id"]
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(json.dumps(message).encode('utf-8'), (recipient_node["ip"], recipient_node["port"]))
            sock.close()
            print(f"Sent direct message to {recipient_node['ip']}:{recipient_node['port']}")
        else:
            # consult routing table
            pass

    def user_interface(self):
        print(f"NODE STARTING WITH FOLLOWING INFO, IP: {self.ip}, PORT: {self.port}, ALIAS: {self.alias}, "
              f"ID: {self.node_id}")
        print("Type /list to see nodes, /msg <alias> <text> to send, /allow to update list of allowed neighbors, "
              "/quit to exit")
        with patch_stdout():
            p = PromptSession()
            while True:
                cmd = p.prompt("> ").strip()
                cmd = cmd.split()
                if len(cmd) == 1:
                    cmd = "".join(cmd)
                    if cmd == "/list":
                        print(self.routing_table)
                    elif cmd == "/quit":
                        print("Quitting...")
                        exit()
                elif len(cmd) >= 2:
                    if cmd[0] == "/msg":
                        try:
                            print("Attempting to send message...")
                            self.send_message(recipient_alias=cmd[1], message=" ".join(cmd[2:]))
                        except Exception as e:
                            print("Failed to send message. Error: ", e)
                    elif cmd[0] == "/allow":
                        neighbors = cmd[1:]
                        self.allow_neighbors(neighbors)
                        print(f"Updated allowed neighbors list: {self.allowed_neighbors}.")

    def allow_neighbors(self, neighbors: list[int]):
        self.allowed_neighbors = [int(port) for port in neighbors]

    def scan_for_routes(self, routing_table: dict):
        for node in routing_table:
            if node == str(self.node_id):
                continue
            elif node not in self.routing_table:
                self.routing_table[node] = {
                    "alias": node["alias"],
                    "hop_count": int(node["hop_count"]) + 1,
                }
            else:
                if node["hop_count"] < self.routing_table[node]["hop_count"]:
                    self.routing_table[node]["hop_count"] = node["hop_count"]
                else:
                    continue
