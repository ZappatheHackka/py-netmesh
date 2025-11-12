import uuid, json, threading, socket, queue, datetime, time, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
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
        self._routing_table = {} #internal use routing table
        self.routes_to_send = {}
        self.captured_packets = []
        self.message_payloads = []
        self._private_key_obj = None
        self._public_key_obj = None
        self.packet_queue = queue.Queue()
        self.message_json = {
            "type": "PROBE",
            "origin": "py_netmesh",
            "alias": None,
            "node_id": str(self.node_id),
            "ip": self.ip,
            "port": self.port,
            "public_key": None,
            "payload": {
                "message": "KLAUS HAAS"
            },
            "routing_table": self.routes_to_send,
        }

    def start(self):
        alias = input("Enter an alias for your node: ").strip()
        self.alias = alias
        self.message_json["alias"] = self.alias
        self._generate_keys()

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
                            # TODO: Reimplement this w/encryption. Search for public keys via node, decrypt
                            try:
                                node_id = [node for node in self._routing_table if node == message["node_id"]]
                                node = self._routing_table[node_id]
                                public_key = node["public_key"]
                                public_key.verify(message["signature"], message["payload"],
                                                  padding.MGF1(algorithm=hashes.SHA256()), hashes.SHA256())
                                plaintext = self._private_key_obj
                            except Exception as e:
                                print(f"Could not verify or decrypt message from {message["alias"]}. Error {e}")

                            print(f"DIRECT MESSAGE FROM {message['alias']}:", message['payload']['message'])
                        else:
                            #TODO check if node_id in routing table
                            if message["destination_id"] in self._routing_table:
                                pass
                            pass
                    elif message["type"] == "PROBE":
                        if message["port"] not in self.allowed_neighbors:
                            continue
                        else:
                            if str(message['node_id']) == str(self.node_id):
                                continue
                            elif message['node_id'] in self._routing_table:
                                time = datetime.datetime.now()
                                self._routing_table[message["node_id"]]["last_seen"] = time
                                self.captured_packets.append(message)
                                self.message_payloads.append(message)
                            else:
                                print(f"New Node found: {message['node_id']} AKA {message['alias']}.")
                                time = datetime.datetime.now()
                                public_key = self._deserialize_pk(message['public_key'])

                                self._routing_table[message["node_id"]] = {
                                    "ip": message["ip"],
                                    "port": message["port"],
                                    "alias": message["alias"],
                                    "hop_count": 1,
                                    "next_hop": message["node_id"],
                                    "public_key": public_key,
                                    "last_seen": time
                                }

                                self.routes_to_send[message["node_id"]] = {
                                    "alias": message["alias"],
                                    "hop_count": 1,
                                    "public_key": public_key,
                                }
                                self.scan_for_routes(routing_table=message["routing_table"],
                                                     parent_id=message["node_id"])
                                self.captured_packets.append(message)
                                self.message_payloads.append(message)
                else:
                    print("'origin' key is designates this message is foreign. Ignoring...\n")
            except KeyError as e:
                if e == "origin":
                    continue # packet not of our mesh, move to next packet
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

        recipient_node = None

        for node_id, info in self._routing_table.items():
            if info.get("alias") == recipient_alias:
                recipient_node = info
                break

        if recipient_node:
            print("Recipient node found!")
            destination_id = recipient_node["next_hop"]
            message = message.strip()

            message = {
                "type": "CHAT",
                "alias": self.alias,
                "recipient": recipient_alias,
                "destination_id": destination_id,
                "origin": "py_netmesh",
                "node_id": str(self.node_id),
                "ip": self.ip,
                "payload": {
                    "message": message,
                },
                "signature": None
            }

            recipient_pk = recipient_node["public_key"]

            encrypted_data = self._encrypt_message(payload=message["payload"], public_key=recipient_pk)
            message["payload"] = encrypted_data

            self._sign(message)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(json.dumps(message).encode('utf-8'), (recipient_node["ip"], recipient_node["port"]))
            sock.close()
            print(f"Sent direct message to {recipient_node['ip']}:{recipient_node['port']}")
        else:
            # TODO How do we handle addresses we have no record of?
            pass

    def user_interface(self):
        print(f"NODE STARTING WITH FOLLOWING INFO, IP: {self.ip}, PORT: {self.port}, ALIAS: {self.alias}, "
              f"ID: {self.node_id}")
        print("Type /list to see nodes, /msg <alias> <text> to send, /allow <port> to update list of allowed neighbors,"
              " /quit to exit")
        with patch_stdout():
            p = PromptSession()
            while True:
                cmd = p.prompt("> ").strip()
                cmd = cmd.split()
                if len(cmd) == 1:
                    cmd = "".join(cmd)
                    if cmd == "/list":
                        print(self._routing_table)
                    elif cmd == "/quit":
                        print("Quitting...")
                        self.stop()
                        exit()
                elif len(cmd) >= 2:
                    if cmd[0] == "/msg":
                        try:
                            print("Attempting to send message...")
                            self.send_message(recipient_alias=cmd[1], message=" ".join(cmd[2:]))
                        except Exception as e:
                            print(f"Failed to send message. Error: {e}")
                    elif cmd[0] == "/allow":
                        neighbors = cmd[1:]
                        self.allow_neighbors(neighbors)
                        print(f"Updated allowed neighbors list: {self.allowed_neighbors}.")

    def allow_neighbors(self, neighbors: list[int]):
        self.allowed_neighbors = [int(port) for port in neighbors]

    def scan_for_routes(self, routing_table: dict, parent_id: str):
        for node in routing_table:
            if node == str(self.node_id):
                continue
            elif node not in self._routing_table:
                self._routing_table[node] = {
                    "alias": routing_table[node]["alias"],
                    "hop_count": int(routing_table[node]["hop_count"]) + 1,
                    "next_hop": parent_id,
                    "public_key": routing_table[node]["public_key"],
                }
            else:
                if routing_table[node]["hop_count"] < self._routing_table[node]["hop_count"]:
                    self._routing_table[node]["hop_count"] = node["hop_count"]
                    self._routing_table[node]["next_hop"] = parent_id
                else:
                    continue

# Internal methods

    # Asymmetric keys
    def _generate_keys(self):
        self._private_key_obj = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = self._private_key_obj.public_key()
        self._public_key_obj = public_key
        public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo)

        public_key_string = public_key_bytes.decode('utf-8')

        self.message_json["public_key"] = public_key_string

    def _encrypt_message(self, payload: dict, public_key):
        json_string = json.dumps(payload, sort_keys=True)
        payload_to_encrypt = json_string.encode('utf-8')

        encrypted_text = public_key.encrypt(payload_to_encrypt,
                                              padding.OAEP(
                                                  mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                  algorithm=hashes.SHA256(),
                                                  label=None
                                              ))
        encrypted_string = base64.b64encode(encrypted_text).decode('utf-8')
        return encrypted_string

    def _sign(self, message: dict):
        payload = message["payload"] # do we need to serialize json if just str? keep for other file types later
        json_string = json.dumps(payload, sort_keys=True)  # convert json to string
        data_to_sign = json_string.encode('utf-8')  # serialize string into bytes for encryption

        signature = self._private_key_obj.sign(data_to_sign, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA256())

        string_signature = base64.b64encode(signature).decode('utf8')
        message["signature"] = string_signature

    def _deserialize_pk(self, pk: str):
        received_pub_key_string = pk
        public_pem_data = received_pub_key_string.encode('utf-8')
        public_key_object = load_pem_public_key(public_pem_data)
        return public_key_object
