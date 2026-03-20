import uuid, json, threading, socket, queue, datetime, time, base64, traceback, pathlib, os, struct, math, signal
from copy import deepcopy
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

class Node:
    def __init__(self, ip: str, port: int, test_mode: bool):
        self.test_mode = test_mode
        self.ip = ip
        self.port = port
        self.node_id = uuid.uuid4()
        self.alias = None
        self.listen_thread = None
        self.discovery_thread = None
        self.file_dir = None # directory incoming files will be stored at
        self.stop_event = threading.Event()
        self.allowed_neighbors = []
        self.neighbor_nodes = []
        self._taken_aliases = []
        self._routing_table = {} # internal use routing table
        self.routes_to_send = {}
        self.sending_engine_registry = {} # registry for file sending engines
        self.file_reception_registry = {} # how we track received keys, seq, etc for file assembly
        self._private_key_obj = None
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
        self.allowed_neighbors.append(self.port + 1)
        self.allowed_neighbors.append(self.port - 1)

        # allows us to interpret OS signals on exit, and blast death packets after terminal closes
        signal.signal(signal.SIGHUP, lambda s, f: self._announce_death())
        signal.signal(signal.SIGTERM, lambda s, f: self._announce_death())

        self._generate_keys()

        self.listen_thread = threading.Thread(target=self.listener_loop, daemon=True)
        self.listen_thread.start()

        self.discovery_thread = threading.Thread(target=self.discovery_loop, daemon=True)
        self.discovery_thread.start()

        self.processor_thread = threading.Thread(target=self.processor, daemon=True)
        self.processor_thread.start()

        self.health_check_thread = threading.Thread(target=self.health_check_loop, daemon=True)
        self.health_check_thread.start()

        self.make_file_dir()
        self.user_interface()

    def listener_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4194304) # increase size of OS recv queue-prevent PL.
        sock.settimeout(1)
        sock.bind(("", self.port))
        while not self.stop_event.is_set():
            data, addr = sock.recvfrom(16000)
            try:
                message = json.loads(data.decode('utf-8'))
                message["ip"] = addr[0]
                if message["node_id"] == str(self.node_id):
                    continue
                else:
                    self.packet_queue.put(message)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"listener error: {e}, moving to next packet.")
                continue

    def health_check_loop(self):
        while not self.stop_event.is_set():
            now = datetime.datetime.now()
            stale = [node_id for node_id, info in self._routing_table.items()
                     if info.get("last_seen") and (now - info["last_seen"]).seconds > 10]
            for node_id in stale:
                print(f"Can no longer reach Node {self._routing_table[node_id]['alias']}.")
                del self._routing_table[node_id]
                if node_id in self.routes_to_send:
                    del self.routes_to_send[node_id]
            time.sleep(5)

    def discovery_loop(self):
        if self.test_mode:
            print("Launching in TEST MODE, using loopback address...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            while not self.stop_event.is_set():
                for neighbor_port in self.allowed_neighbors:
                    sock.sendto(json.dumps(self.message_json).encode('utf-8'),
                                ('127.0.0.1', neighbor_port))
                time.sleep(5)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            while not self.stop_event.is_set():
                sock.sendto(json.dumps(self.message_json).encode('utf-8'), ('255.255.255.255', self.port))
                time.sleep(5)

    def processor(self):
        while not self.stop_event.is_set():
            try:
                message = self.packet_queue.get(timeout=1)
            except queue.Empty:
                continue
            try:
                if message["origin"] == "py_netmesh":
                    if message["type"] is not None:
                        match message["type"]:
                            case "PROBE":
                                if str(message['node_id']) == str(self.node_id):
                                    continue
                                elif message["port"] not in self.allowed_neighbors:
                                    continue
                                else:
                                    self._handle_probe_packet(message=message)
                            case "ACK":
                                self._handle_ack_message(message=message)
                            case "CHAT":
                                self._handle_chat_message(message=message)
                            case "CHUNK":
                                self._handle_chunk_message(message=message)
                            case "DEATH":
                                self._handle_death_packet(message=message)
                    else:
                        print("Processor detected py_netmesh packet 'type' key had value of Nonetype. DEBUG!!")
                else:
                    print("'origin' key is designates this message is foreign. Ignoring...\n")
            except KeyError as e:
                if e == "origin":
                    continue
                else:
                    print("KeyError: ", e)
                    traceback.print_exc()

    def stop(self):
        print("Stopping node...")
        self._announce_death()
        self.stop_event.set()
        self.listen_thread.join()
        self.discovery_thread.join()
        self.processor_thread.join()
        print("Node stopped cleanly.")

    def send_message(self, recipient_alias: str, message: str):

        recipient_dict = {}
        node_key = ""

        for node_id, info in self._routing_table.items():
            if info.get("alias") == recipient_alias:
                recipient_dict[node_id] = info
                node_key = node_id
                break

        if recipient_dict != {} and node_key != "":
            if recipient_dict[node_key]['hop_count'] == 1:

                message = message.strip()

                message = {
                    "type": "CHAT",
                    "alias": self.alias,
                    "recipient": recipient_alias,
                    "origin": "py_netmesh",
                    "node_id": str(self.node_id),
                    "destination_id": node_key,
                    "ip": self.ip,
                    "payload": {
                        "message": message,
                    },
                    "signature": None
                }

                recipient_pk = recipient_dict[node_key]["public_key"]
                recipient_pk = self._serialize_pk(recipient_pk)

                encrypted_data = self._encrypt_message(payload=message["payload"], public_key=recipient_pk)
                message["payload"] = encrypted_data

                self._sign(message)

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(json.dumps(message).encode('utf-8'),
                            (recipient_dict[node_key]["ip"], recipient_dict[node_key]["port"]))
                sock.close()
                print(f"Sent message to {message['recipient']}!")

            elif recipient_dict[node_key]["hop_count"] > 1:
                next_hop = recipient_dict[node_key]["next_hop"]

                next_node = self._routing_table[next_hop]

                message = {
                    "type": "CHAT",
                    "alias": self.alias,
                    "recipient": recipient_alias,
                    "origin": "py_netmesh",
                    "node_id": str(self.node_id),
                    "destination_id": node_key,
                    "ip": self.ip,
                    "payload": {
                        "message": message,
                    },
                    "signature": None
                }

                recipient_pk = recipient_dict[node_key]["public_key"]
                recipient_pk = self._serialize_pk(recipient_pk)

                encrypted_data = self._encrypt_message(payload=message["payload"], public_key=recipient_pk)
                message["payload"] = encrypted_data

                self._sign(message)

                self._forward_message(next_node=next_node, message=message)
        else:
            if recipient_alias == self.alias:
                print(f"{recipient_alias} is your own alias. Try another.")
            else:
                print(f"Could not send message, node {recipient_alias} not in routing table.")

    def send_file(self, recipient_alias: str, file_path: pathlib.Path):
        recipient_dict = {}
        node_key = ""

        for node_id, info in self._routing_table.items():
            if info.get("alias") == recipient_alias:
                recipient_dict[node_id] = info
                node_key = node_id
                break

        if recipient_dict != {} and node_key != "":
            file_id = str(uuid.uuid4())
            routing_table_copy = deepcopy(self._routing_table)

            engine = Engine()
            engine._routing_table = routing_table_copy
            engine.recipient_dict = recipient_dict
            engine.recipient_id = node_key
            self.sending_engine_registry[file_id] = engine

            message = {
                "type": "CHUNK",
                "alias": self.alias,
                "recipient": recipient_alias,
                "origin": "py_netmesh",
                "recipient_pk": recipient_dict[node_key]["public_key"],
                "encrypted_session_key": None,
                "nonce": None,
                "session_key": None,
                "node_id": str(self.node_id),
                "destination_id": node_key,
                "ip": self.ip,
                "file_id": file_id,
                "hop_count": recipient_dict[node_key]["hop_count"],
                "seq": None,
                "final": False,
                "payload": {
                    "data": None,
                    "filename": str(file_path.name),
                },
                "signature": None
            }

            engine.start(id=file_id ,filepath=file_path, message_data=message)
        else:
            print(f"Cannot send file, alias {recipient_alias} not in routing table.")

    def user_interface(self):
        print(f"NODE STARTING WITH FOLLOWING INFO, IP: {self.ip}, PORT: {self.port}, ALIAS: {self.alias}, "
              f"ID: {self.node_id}\n")
        print("Type /list to see nodes, /msg <alias> <text> to chat, /allow <port> to update list of allowed neighbors,"
              " /send_file <alias> <filepath> to send files, /change_filedir <filepath> to change where incoming files "
              "are received, and /quit to exit\n")
        print(f"Your current directory is {pathlib.Path.cwd()}")
        with patch_stdout():
            p = PromptSession()
            while True:
                cmd = p.prompt("> ").strip()
                cmd = cmd.split()
                if len(cmd) == 1:
                    cmd = "".join(cmd)
                    match cmd:
                        case "/list": # refine for users
                            print(self._routing_table.keys())
                        case "/quit":
                            print("Quitting...")
                            self.stop()
                            exit()
                        case "/rts":
                            print(f"PRIVATE ROUTING TABLE: {self._routing_table}\n"
                                f"ROUTES TO SEND: {self.routes_to_send}")
                elif len(cmd) >= 2:
                    match cmd[0]:
                        case "/msg":
                            try:
                                print("Attempting to send message...")
                                self.send_message(recipient_alias=cmd[1], message=" ".join(cmd[2:]))
                            except Exception as e:
                                print(f"Failed to send message. Error: {e}")
                                traceback.print_exc()
                        case "/allow":
                            neighbors = cmd[1:]
                            self.allow_neighbors(neighbors)
                            print(f"Updated allowed neighbors list: {self.allowed_neighbors}.")
                        case "/change_filedir":
                            new_path = cmd[1]
                            path = self.file_dir
                            self.file_dir = new_path
                            print(f"You will now receive files at {new_path} instead of {path}.")
                        case "/send_file":
                            recipient = cmd[1]
                            filepath = cmd[2].strip("'\"")
                            path = pathlib.Path(filepath).expanduser().resolve()
                            if not path.exists():
                                print(f"File {path} does not exist. Enter a different filepath and try again.")
                            elif not path.is_file():
                                print(f"File {path} does not point to a file. Enter a different filepath and try again.")
                            else:
                                print("Attempting to send file...")
                                self.send_file(recipient_alias=recipient, file_path=path)

    def allow_neighbors(self, neighbors: list[int]):
        new_neighbors = [int(port) for port in neighbors]
        for neighbor in new_neighbors:
            if neighbor in self.allowed_neighbors:
                print(f"Port {neighbor} is already allowed.")
            else:
                self.allowed_neighbors.append(neighbor)

# Internal methods

    # Asymmetric keys
    def _generate_keys(self):
        self._private_key_obj = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = self._private_key_obj.public_key()
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

    def _handle_chat_message(self, message: dict):
        if message["destination_id"] == str(self.node_id):
            try:
                decrypted_message = self._decrypt_message(message=message)
                print(f"{message['alias']}: {decrypted_message['payload']['message']}")
            except Exception as e:
                print(f"Could not verify or decrypt message from {message["alias"]}. Error {e}")
        elif message["destination_id"] is not None:
            next_node = self._find_node(alias=message["recipient"])
            self._forward_message(message=message, next_node=next_node)
            print(f"Message forwarded, alias is {message['recipient']}")

    def _handle_probe_packet(self, message: dict):
        time = datetime.datetime.now()
        if message['alias'] == str(self.alias):
            print(f"Duplicate alias detected. Updating your alias for uniqueness.")
            self._update_alias()
        if message['node_id'] in self._routing_table:
            if message['alias'] != self._routing_table[message['node_id']]['alias']:
                print(f"NOTICE: Node {self._routing_table[message['node_id']]['alias']} "
                      f"is changing to alias {message['alias']}.")

            self._routing_table[message["node_id"]]["last_seen"] = time
            self._routing_table[message["node_id"]]["alias"] = message["alias"]
            self.routes_to_send[message["node_id"]]['alias'] = message['alias']

            self._scan_for_routes(routing_table=message["routing_table"],
                                  parent_id=message["node_id"], time=time)
        else:
            print(f"New Neighbor Node found: {message['alias']}.")

            public_key = self._deserialize_pk(message['public_key']) # convert to bytes to avoid PICKLE ERROR from DEEPCOPY
            serialized_pub_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)

            self._routing_table[message["node_id"]] = {
                "ip": message["ip"],
                "port": message["port"],
                "alias": message["alias"],
                "hop_count": 1,
                "next_hop": message["node_id"],
                "public_key": serialized_pub_key,
                "last_seen": time
            }

            self.neighbor_nodes.append(message["alias"])

            self.routes_to_send[message["node_id"]] = {
                "alias": message["alias"],
                "hop_count": 1,
                "public_key": message['public_key'],
                "next_hop": message["node_id"],
            }

            self._scan_for_routes(routing_table=message["routing_table"],
                                  parent_id=message["node_id"], time=time)
            self._taken_aliases.append(message["alias"])

    def _handle_chunk_message(self, message: dict):
        if message["destination_id"] == str(self.node_id):
            try:
                encrypted_payload = base64.b64decode(message["payload"])
                nonce = base64.b64decode(message["nonce"])
                seq = message["seq"]
                file_id = message["file_id"]
                alias = message["alias"]
                if seq == 1:
                    session_key = message["session_key"]
                    window_size = message["window_size"]
                    key_bytes = base64.b64decode(session_key.encode('utf-8'))
                    decrypted_session_key = self._private_key_obj.decrypt(key_bytes,
                                                                          padding.OAEP(
                                                           mgf=padding.MGF1(hashes.SHA256()),
                                                           algorithm=hashes.SHA256(),
                                                           label=None
                                                        )    )
                    self.file_reception_registry[file_id] = {}
                    self.file_reception_registry[file_id]["session_key"] = decrypted_session_key
                    self.file_reception_registry[file_id]["window_size"] = window_size
                    self.file_reception_registry[file_id]["seq"] = seq
                    self.file_reception_registry[file_id]["accepted_seq"] = 0
                    self.file_reception_registry[file_id]["file_handle"] = None
                    self.file_reception_registry[file_id]["alias"] = alias
                    self.file_reception_registry[file_id]["chunks"] = []

                aes_key = self.file_reception_registry[file_id]["session_key"]
                window_size = self.file_reception_registry[file_id]["window_size"]

                if seq > 1:
                    if seq <= self.file_reception_registry[file_id]["seq"]:
                        print(f"Lagging seq incoming. We have {self.file_reception_registry[file_id]['seq']}, incoming"
                              f" is {seq}. Likely resent packets. Resending ACK...")
                        # resend last ACK message here
                        self._send_ack(message=self.file_reception_registry[file_id]["prev_chunk"],
                                       seq=self.file_reception_registry[file_id]["accepted_seq"],
                                       file_id=file_id, final=False, status="ok", key=aes_key)
                        return
                    elif seq != (self.file_reception_registry[file_id]["seq"] + 1):
                        print(f"WARNING, incoming chunk is seq {seq}, while we are expecting "
                              f"{(self.file_reception_registry[file_id]["seq"] + 1)}.")
                        self._send_ack(message=message, file_id=file_id, status="seq_mismatch", final=False,
                                       key=aes_key, seq=seq)
                        return
                    else:
                        self.file_reception_registry[file_id]["seq"] = seq
                        print(f"PACKET SEQ: {seq}, STORED SEQ: {self.file_reception_registry[file_id]["seq"]}")
                        self.file_reception_registry[file_id]["accepted_seq"] = seq

                plaintext_json = self._decrypt_chunk(key=self.file_reception_registry[file_id]["session_key"],
                                    seq=self.file_reception_registry[file_id]["seq"],
                                    file_id=uuid.UUID(file_id).bytes, nonce=nonce,
                                    encrypted_payload=encrypted_payload)

                if seq == 1:
                    filename = plaintext_json["filename"]
                    self.file_reception_registry[file_id]["filename"] = filename
                    save_path = os.path.join(self.file_dir, filename)
                    self.file_reception_registry[file_id]["save_path"] = save_path

                save_path = self.file_reception_registry[file_id]["save_path"]
                filename = self.file_reception_registry[file_id]["filename"]

                plaintext_bytes = plaintext_json["data"]
                plaintext_bytes = base64.b64decode(plaintext_bytes.encode('utf-8'))

                if self.file_reception_registry[file_id]["file_handle"] is None:
                    file_handle = open(save_path, "wb")
                    self.file_reception_registry[file_id]["file_handle"] = file_handle

                file_handle = self.file_reception_registry[file_id]["file_handle"]

                if seq % window_size != 0:
                    self.file_reception_registry[file_id]["chunks"].append(plaintext_bytes)
                elif seq % window_size == 0:
                    self.file_reception_registry[file_id]["accepted_seq"] = seq
                    self.file_reception_registry[file_id]["prev_chunk"] = message
                    self.file_reception_registry[file_id]["chunks"].append(plaintext_bytes)
                    file_handle.write(b"".join(self.file_reception_registry[file_id]["chunks"]))
                    file_handle.flush()
                    self.file_reception_registry[file_id]["chunks"] = []
                    self._send_ack(message=message, file_id=file_id, final=False, status="ok", key=aes_key, seq=seq)

                if message["final"] == True:
                    self._send_ack(message=message, file_id=file_id, final=True, status="ok", key=aes_key, seq=seq)
                    print(f"FILE RECEIVED: {filename} at {self.file_dir}/{filename} from {message['alias']}")
                    file_handle.write(b"".join(self.file_reception_registry[file_id]["chunks"]))
                    file_handle.flush()
                    file_handle.close()
                    self.file_reception_registry[file_id]["file_handle"] = None

            except Exception as e:
                print(f"Could not process received chunk packet. Error {e}")
                traceback.print_exc()

        elif message["destination_id"] is not None:
            next_node = self._find_node(alias=message["recipient"])
            self._forward_message(next_node=next_node, message=message)

    def _handle_ack_message(self, message: dict):
        if str(message["destination_id"]) == str(self.node_id):

            nonce = message["nonce"]
            nonce = bytes(nonce, "utf-8")

            our_engines = set()
            for engine in self.sending_engine_registry.values():
                if str(engine.recipient_id) == str(message["node_id"]):
                    our_engines.add(engine)

            decrypted_payload = self._decrypt_ack(our_engines=our_engines, message=message)
            print(f"ACK received with seq {decrypted_payload['seq']}")
            file_id = str(decrypted_payload["file_id"])
            engine = self.sending_engine_registry[file_id]

            if decrypted_payload["status"] == "seq_mismatch":
                print(f"MISMATCHING SEQ DETECTED! FILE TRANSFER TO {message['alias']} CANCELLED.")
                engine.stop_sending.set()
                return
            else:
                ack_seq = decrypted_payload["seq"]
                engine.confirm_ack(ack_seq)

                if decrypted_payload["final"] == True:
                    print(f"FILE SUCCESSFULLY SENT: {decrypted_payload["filename"]}.\nFINAL ACK MESSAGE RECEIVED, "
                          f"DESTROYING ENGINE RESPONSIBLE FOR FILE {decrypted_payload["filename"]}")
                    engine.stop_sending.set()
                    engine = None
                    del self.sending_engine_registry[file_id]
                    return

        else:
            next_node = self._find_node(alias=message["recipient"])
            self._forward_message(message=message, next_node=next_node)

    def _handle_death_packet(self, message: dict):
        if message["node_id"] == str(self.node_id):
            pass
        else:
            if message["node_id"] in self._routing_table.keys() and message["node_id"] in self.routes_to_send.keys():

                print(f"NODE DEATH DETECTED: {message['alias']} has left the mesh.")
                print("Other nodes may now be unreachable.")

                del self._routing_table[message["node_id"]]
                del self.routes_to_send[message["node_id"]]

                json_string = json.dumps(message, sort_keys=True).encode("utf-8")

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                for node in self.neighbor_nodes:
                    try:
                        if node == message["alias"]:
                            continue
                        neighbor = self._find_node(node)
                        sock.sendto(json_string, (neighbor["ip"], neighbor["port"]))
                    except TypeError:
                        pass
                sock.close()
            else:
                pass

    def _announce_death(self): # for node dropout announcements
        message = {
            "type": "DEATH",
            "origin": "py_netmesh",
            "node_id": str(self.node_id),
            "alias": self.alias,
        }

        json_string = json.dumps(message, sort_keys=True).encode("utf-8")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        for node in self.neighbor_nodes:
            try:
                neighbor = self._find_node(node)
                sock.sendto(json_string, (neighbor["ip"], neighbor["port"]))
            except TypeError:
                pass
        sock.close()

    def _send_ack(self, message: dict, file_id: str, final: bool, status: str, seq: int, key):
        bytenonce = os.urandom(12)
        nonce = base64.b64encode(bytenonce).decode("utf-8")

        ack_message = {
            "type": "ACK",
            "alias": message["recipient"],
            "recipient": message["alias"],
            "origin": "py_netmesh",
            "node_id": str(self.node_id),
            "destination_id": "",
            "ip": self.ip,
            "nonce": nonce,
            "payload": {
                "seq": seq,
                "file_id": file_id,
                "filename": str(self.file_reception_registry[file_id]["filename"]),
                "status": status,
                "final": final
            }
        }

        recipient_alias = message["alias"]

        recipient_dict = {}
        node_key = ""

        for node_id, info in self._routing_table.items():
            if info.get("alias") == recipient_alias:
                recipient_dict[node_id] = info
                node_key = node_id
                break

        if recipient_dict != {} and node_key != "":

            ack_message["destination_id"] = str(node_key)

            if recipient_dict[node_key]['hop_count'] == 1:

                encrypted_data = self._encrypt_ack(payload=ack_message["payload"], key=key, nonce=bytenonce)
                ack_message["payload"] = encrypted_data

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(json.dumps(ack_message).encode('utf-8'),
                            (recipient_dict[node_key]["ip"], recipient_dict[node_key]["port"]))
                sock.close()
                print(f"Ack message for chunk {message["seq"]} sent to {message['alias']}!")
            else:
                next_hop = recipient_dict[node_key]["next_hop"]
                next_node = self._routing_table[next_hop]

                encrypted_data = self._encrypt_ack(payload=ack_message["payload"], key=key, nonce=bytenonce)
                ack_message["payload"] = encrypted_data

                self._forward_message(next_node=next_node, message=ack_message)

    def _decrypt_message(self, message: dict):
        sender_id = message["node_id"]
        if sender_id in self._routing_table:
            sender_info = self._routing_table[sender_id]
            sender_public_key = sender_info["public_key"]
            sender_public_key = self._serialize_pk(sender_public_key)

            if message["type"] == "CHAT":
                signature_bytes = base64.b64decode(message["signature"].encode('utf-8'))

                data_to_verify = json.dumps(message["payload"], sort_keys=True).encode('utf-8')

                sender_public_key.verify(
                    signature=signature_bytes,
                    data=data_to_verify,
                    padding=padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    algorithm=hashes.SHA256()
                )

            encrypted_payload_string = message["payload"]

            encrypted_payload_bytes = base64.b64decode(encrypted_payload_string.encode('utf-8'))

            plaintext_bytes = self._private_key_obj.decrypt(
                ciphertext=encrypted_payload_bytes,
                padding=padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            plaintext_string = plaintext_bytes.decode('utf-8')
            original_payload_dict = json.loads(
                plaintext_string)

            message["payload"] = original_payload_dict

            return message

        else:
            print(f"Sender not in routing table. Suspending decryption...")
            return None

    def _encrypt_ack(self, payload: dict, key, nonce):
        json_string = json.dumps(payload, sort_keys=True)
        payload_to_encrypt = json_string.encode('utf-8')

        aesgcm = AESGCM(key)

        encrypted_payload = aesgcm.encrypt(data=payload_to_encrypt, associated_data=None, nonce=nonce)
        encrypted_payload = base64.b64encode(encrypted_payload).decode('utf-8')

        return encrypted_payload

    def _decrypt_ack(self, message: dict, our_engines: set):
        encrypted_payload_bytes = base64.b64decode(message["payload"])
        bytenonce = base64.b64decode(message["nonce"])
        for engine in our_engines:
            try:
                aesgcm = AESGCM(engine.aes_key)
                decrypted_bytes = aesgcm.decrypt(data=encrypted_payload_bytes, associated_data=None, nonce=bytenonce)
                plaintext_data = decrypted_bytes.decode('utf-8')
                plaintext_json = json.loads(plaintext_data)
                return plaintext_json
            except InvalidTag:
                print("Could not decrypt", InvalidTag)
                traceback.print_exc()
                continue
            except Exception as e:
                print(e)
        print("Could not find key, cannot decrypt ACK message.")
        return None

    def _forward_message(self, next_node: dict, message: dict):
        ip = next_node["ip"]
        port = next_node["port"]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(json.dumps(message).encode('utf-8'), (ip, port))
            sock.close()
            print(f"{self.alias} forwarded message to {next_node['alias']}. Message for {message['recipient']}")
        except Exception as e:
            print(f"An unexpected error occurred during forwarding: {e}")

    def _decrypt_chunk(self, file_id, key, seq, nonce, encrypted_payload):
        aad = struct.pack('!16sI', file_id, seq)
        aesgcm = AESGCM(key)

        try:
            decrypted_bytes = aesgcm.decrypt(data=encrypted_payload, nonce=nonce, associated_data=aad)
            plaintext_data = decrypted_bytes.decode('utf-8')
            plaintext_json = json.loads(plaintext_data)
            return plaintext_json

        except InvalidTag as e:
            print(f"Could not decrypt file chunk {seq}. Error {e}")
            return None

    def _sign(self, message: dict):
        payload = message["payload"]
        json_string = json.dumps(payload, sort_keys=True)
        data_to_sign = json_string.encode('utf-8')

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

    def _serialize_pk(self, pk):
        if (type(pk)) is not bytes:
            pk = pk.encode('utf-8')
        pub_key = load_pem_public_key(pk)
        return pub_key

    def _scan_for_routes(self, routing_table: dict, parent_id: str, time: datetime):
        for node in routing_table:
            if node == str(self.node_id):
                continue
            elif node not in self._routing_table:
                self._routing_table[node] = {
                    "alias": routing_table[node]["alias"],
                    "hop_count": int(routing_table[node]["hop_count"]) + 1,
                    "next_hop": parent_id,
                    "public_key": routing_table[node]["public_key"],
                    "last_seen": time
                }
                self.routes_to_send[node] = {
                    "alias": routing_table[node]["alias"],
                    "hop_count": int(routing_table[node]["hop_count"]) + 1,
                    "next_hop": parent_id,
                    "public_key": routing_table[node]["public_key"],
                }
                print(f"New Node found via PROBE: {self._routing_table[node]['alias']}")
            else:
                self._routing_table[node]["last_seen"] = time
                if int(routing_table[node]["hop_count"]) < int(self._routing_table[node]["hop_count"]):
                    self._routing_table[node]["hop_count"] = int(self._routing_table[node]["hop_count"])
                    self._routing_table[node]["next_hop"] = parent_id
                else:
                    continue

    def _find_node(self, alias: str): # search until hop_count == 1
        try:
            for node, info, in self._routing_table.items():
                if info["alias"] == alias:
                    node = self._routing_table[node]
                    if node["hop_count"] == 1:
                        return node
                    else:
                        node = self._routing_table[node["next_hop"]]
                        return node
            print(f"Cannot find node for {alias}. Node has either dropped from the mesh, or your path to it has been"
                  f" severed.")
            return None
        except Exception:
            return None

    def _update_alias(self):
        nums = str(self.node_id)[:3]
        old = self.alias
        new_alias = self.alias + nums
        self.alias = new_alias
        print(f"Alias {old} updated to {new_alias}.")
        self.message_json['alias'] = new_alias

    def make_file_dir(self):
        path = pathlib.Path("py_netmesh_received_files")
        self.file_dir = path
        self.file_dir.mkdir(parents=True, exist_ok=True)

class Engine:
    def __init__(self):
        self.seq = 1
        self.chunk_num = 0
        self.window_size = 0
        self.current_window = {}
        self.file_uuid = None
        self.ack_received = threading.Event()
        self.stop_sending = threading.Event()
        self.chunk_queue = queue.Queue()
        self.recipient_dict = {}
        self._routing_table = {}
        self.recipient_id = None
        self.aes_key = None

    def start(self, id: str, filepath, message_data: dict):
        self.file_uuid = id
        chunk_processing = threading.Thread(target=self.process_chunks, args=(filepath, message_data),daemon=True)
        chunk_processing.start()
        return chunk_processing

    def process_chunks(self, filepath: str, message_data: dict):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.file_uuid = message_data["file_id"]

        chunk_size = 8192
        self.chunk_num = self.number_of_chunks(filepath=filepath, chunk_size=chunk_size)

        self.window_size = self._calc_window_size(hop_count=message_data["hop_count"])
        print(f"WINDOW SIZE CALCULATED TO BE {self.window_size}")
        message_data["window_size"] = self.window_size
        del message_data["hop_count"]

        print(f"CHUNKS TO SEND: {self.chunk_num}")
        next_hop = self.find_next_hop()

        session_key = AESGCM.generate_key(256)
        self.aes_key = session_key
        if type(message_data["recipient_pk"]) is str:
            message_data["recipient_pk"] = message_data["recipient_pk"].encode('utf-8')
        public_key = self._deserialize_pk(message_data["recipient_pk"])

        del message_data["recipient_pk"]
        aesgcm = AESGCM(session_key)
        encrypted_session_key = public_key.encrypt(session_key,
                                                   padding.OAEP(
                                                       mgf=padding.MGF1(hashes.SHA256()),
                                                       algorithm=hashes.SHA256(),
                                                       label=None
                                                   )
                                                )
        session_key = base64.b64encode(encrypted_session_key).decode('utf-8')
        while not self.stop_sending.is_set():
            try:
                for chunk in self.fetch_chunk(size=chunk_size, path=filepath):
                    if self.stop_sending.is_set():
                        break
                    data_to_send = deepcopy(message_data)
                    print(f"seq {self.seq}, chunk num {self.chunk_num}")
                    data_to_send["session_key"] = session_key
                    data_to_send["seq"] = self.seq
                    if data_to_send["seq"] == self.chunk_num:
                        data_to_send["final"] = True

                    encrypted_chunk_data = self.encrypt_chunk(chunk, data_to_send, aesgcm)
                    self.current_window[self.seq] = encrypted_chunk_data
                    self.chunk_queue.put(encrypted_chunk_data)

                    if self.seq > 1:
                        if (self.seq - 1) % self.window_size == 0:
                            if not self.ack_received.wait(timeout=2.0):
                                print(f"Timed out waiting for ACK for chunk {self.seq - 1}")
                                print(f"Resending chunks {self.current_window.keys()}...")
                                self.ack_received.clear()
                                self._resend_chunks(next_hop=next_hop, sock=sock, final=data_to_send["final"])
                                if not self.ack_received.wait(timeout=5.0):
                                    print("Window resend failed. Canceling file transfer.")
                                    self.stop_sending.set()
                                break
                            else:
                                self.ack_received.clear()
                                self.current_window = {}


                    self.send_chunk(next_hop=next_hop, sock=sock)
                    if data_to_send["final"] is True:
                        print("Final chunk sent, halting engine...")
                        print(f"WINDOW SIZE CALCULATED TO BE {self.window_size}")
                        self.stop_sending.set()
                        break

                    if self.seq == 1:
                        del message_data["session_key"]
                        del message_data["window_size"]
                    self.seq += 1
            except Exception as e:
                print(f"Chunk sending failed, error: {e}")
                traceback.print_exc()

    def fetch_chunk(self, size: int, path: str):
        with open(file=path, mode="rb") as f:
            while True:
                chunk = f.read(size)
                if not chunk:
                    break
                yield chunk

    def send_chunk(self, next_hop, sock):
        chunk_data = self.chunk_queue.get()
        json_string = json.dumps(chunk_data, sort_keys=True)
        json_bytes = json_string.encode('utf-8')

        sock.sendto(json_bytes, (next_hop["ip"], next_hop["port"]))

    def _resend_chunks(self, next_hop, sock, final: bool):
        for chunk in self.current_window.values():
            json_string = json.dumps(chunk, sort_keys=True)
            json_bytes = json_string.encode('utf-8')
            sock.sendto(json_bytes, (next_hop["ip"], next_hop["port"]))
            if final is True:
                print("Final chunk sent, halting engine...")
                print(f"WINDOW SIZE CALCULATED TO BE {self.window_size}")
                self.stop_sending.set()
                break

    def confirm_ack(self, ack_seq: int):
        if ack_seq in self.current_window:
            self.ack_received.set()
        else:
            print(f"ERROR: ACK seq {ack_seq} not in current window {list(self.current_window.keys())}")

    def encrypt_chunk(self, chunk, message_data: dict, aesgcm: AESGCM) -> dict:
        payload = message_data["payload"]
        payload["data"] = base64.b64encode(chunk).decode('utf-8')
        payload_bytes = json.dumps(payload).encode('utf-8')

        nonce = os.urandom(12)
        message_data["nonce"] = base64.b64encode(nonce).decode('utf-8')

        file_id = uuid.UUID(self.file_uuid).bytes
        aad = struct.pack('!16sI', file_id, self.seq)

        encrypted_payload = aesgcm.encrypt(data=payload_bytes, nonce=nonce, associated_data=aad)
        encrypted_payload = base64.b64encode(encrypted_payload).decode('utf-8')
        message_data["payload"] = encrypted_payload

        return message_data

    def find_next_hop(self):
        next_hop = self.recipient_dict[self.recipient_id]["next_hop"]
        next_node = self._routing_table[next_hop]
        return next_node

    def number_of_chunks(self, filepath: str, chunk_size: int) -> int:
        file_size = os.path.getsize(filepath)
        print(f"CHUNK NUM CALC: {file_size} / {chunk_size}")
        return math.ceil(file_size / chunk_size)

    def _deserialize_pk(self, pk: bytes):
        public_key_object = load_pem_public_key(pk)
        return public_key_object

    def _calc_window_size(self, hop_count: int) -> int:
        if hop_count >= 3:
            window_size = hop_count * 4
            if window_size > 28:
                window_size = 28
        else:
            window_size = hop_count * 8
        return window_size + 2