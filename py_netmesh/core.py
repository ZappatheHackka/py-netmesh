import uuid, json, threading, socket, queue, datetime, time, base64, traceback, pathlib, os, struct
from copy import deepcopy
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
        self.file_dir = None # directory incoming files will be stored at
        self.stop_event = threading.Event()
        self.allowed_neighbors = []
        self._routing_table = {} #internal use routing table
        self.routes_to_send = {}
        self.sending_engine_registry = {} # registry for file sending engines
        self.file_reception_registry = {} # how we track received keys, seq, etc for file assembly
        self._thread_registry = {} # registry for threads of file sending operations, health checks etc
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
        self.allowed_neighbors.append(self.port + 1)
        self.allowed_neighbors.append(self.port - 1)

        self._generate_keys()

        self.listen_thread = threading.Thread(target=self.listener_loop, daemon=True)
        self.listen_thread.start()

        self.discovery_thread = threading.Thread(target=self.discovery_loop, daemon=True)
        self.discovery_thread.start()

        self.processor_thread = threading.Thread(target=self.processor, daemon=True)
        self.processor_thread.start()

        self.make_file_dir()
        self.user_interface()

    def listener_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", self.port))
        print("Listening thread now active...")
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                message = json.loads(data.decode('utf-8'))
                message["ip"] = addr[0]
                #TODO: REMOVE
                if message["alias"] == self.alias:
                    continue
                else:
                    self.packet_queue.put(message)
            except Exception as e:
                print(f"listener error: {e}, moving to next packet.")
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
                    if message["type"] is not None:
                        match message["type"]:
                            case "PROBE": # keep own probe check outside func, don't need to process own probes
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
                    else:
                        print("Processor detected py_netmesh packet 'type' key had value of Nonetype. DEBUG!!")
                else:
                    print("'origin' key is designates this message is foreign. Ignoring...\n")
            except KeyError as e:
                if e == "origin":
                    continue # packet not of our mesh, move to next packet
                else:
                    print("KeyError: ", e)
                    traceback.print_exc()

    def stop(self):
        print("Stopping node...")
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
                "seq": None,
                "final": False,
                "payload": {
                    "data": None,
                    "filename": str(file_path.name),
                },
                "signature": None
            }

            thread = engine.start(id=file_id ,filepath=file_path, message_data=message)
            self._thread_registry[file_id] = thread
        else:
            print(f"Cannot send file, alias {recipient_alias} not in routing table.")

# TODO: CLEAN UP
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
                        case "/list":
                            print(self._routing_table)
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
                            neighbors = [int(neighbor) for neighbor in neighbors]
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
        if len(self.allowed_neighbors) == 0:
            self.allowed_neighbors = [int(port) for port in neighbors]
        else:
            new_neighbors = [int(port) for port in neighbors]
            self.allowed_neighbors.extend(new_neighbors)

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
        # convert json dict into flat, consistent string
        json_string = json.dumps(payload, sort_keys=True)
        # convert string into bytes to encrypted
        payload_to_encrypt = json_string.encode('utf-8')


        #TODO [DONE] Handle nodes found via Probe routing table; their pub key is store as str not obj
        encrypted_text = public_key.encrypt(payload_to_encrypt,
                                              padding.OAEP(
                                                  mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                  algorithm=hashes.SHA256(),
                                                  label=None
                                              ))
        # convert post-encrypt bytes back into string. b64 for safety
        encrypted_string = base64.b64encode(encrypted_text).decode('utf-8')
        return encrypted_string

    def _handle_chat_message(self, message: dict):
        if message["destination_id"] == str(self.node_id):
            try:
                decrypted_message = self._decrypt_message(message=message)
                print(f"{message['alias']}: {decrypted_message['payload']['message']}")
            except Exception as e:
                print(f"Could not verify or decrypt message from {message["alias"]}. Error {e}")
        # TODO [DONE] check if node_id in routing table - make func that forwards to next hop
        elif message["destination_id"] is not None:
            next_node = self._find_node(alias=message["recipient"])  # ALIAS IS SENDER NOT RECP.
            self._forward_message(message=message, next_node=next_node)
            print(f"Message forwarded, alias is {message['recipient']}")

    def _handle_probe_packet(self, message: dict):
        if message['node_id'] in self._routing_table:
            time = datetime.datetime.now()
            self._routing_table[message["node_id"]]["last_seen"] = time
            self._scan_for_routes(routing_table=message["routing_table"],
                                  parent_id=message["node_id"])
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
                "public_key": message['public_key'],
                "next_hop": message["node_id"],
            }
            self._scan_for_routes(routing_table=message["routing_table"],
                                  parent_id=message["node_id"])
            self.captured_packets.append(message)
            self.message_payloads.append(message)

    def _handle_chunk_message(self, message):
        # deserialize
        # decrypt
        # assemble
        if message["destination_id"] == str(self.node_id):
            try:
                encrypted_payload = base64.b64decode(message["payload"])
                nonce = base64.b64decode(message["nonce"])
                seq = message["seq"]
                file_id = message["file_id"]
                if seq == 0:
                    session_key = message["session_key"]
                    decrypted_session_key = self._private_key_obj.decrypt(session_key,
                                                                          padding.OAEP(
                                                           mgf=padding.MGF1(hashes.SHA256()),
                                                           algorithm=hashes.SHA256(),
                                                           label=None
                                                        )    )
                    self.file_reception_registry[file_id] = {}
                    self.file_reception_registry[file_id]["session_key"] = decrypted_session_key
                    self.file_reception_registry[file_id]["file_handle"] = None

                if seq != (self.file_reception_registry[file_id]["seq"] + 1):
                    print(f"WARNING, incoming chunk is seq {seq}, while we are expecting "
                          f"{(self.file_reception_registry[file_id]["seq"] + 1)}."
                          f"\nStopping file send engine.")
                    self._send_ack(message=message, file_id=file_id, status="seq_mismatch", final=False)
                else:

                    self.file_reception_registry[file_id]["seq"] = seq

                    plaintext_json = self._decrypt_chunk(key=self.file_reception_registry[file_id]["session_key"],
                                        seq=self.file_reception_registry[file_id]["seq"],
                                        file_id=uuid.UUID(file_id).bytes, nonce=nonce,
                                        encrypted_payload=encrypted_payload)

                    filename = plaintext_json["payload"]["filename"]
                    self.file_reception_registry[file_id]["filename"] = filename
                    save_path = os.path.join(self.file_dir, filename)
                    plaintext_bytes = plaintext_json["payload"]["data"]

                    if self.file_reception_registry[file_id]["file_handle"] is None:
                        file_handle = open(save_path, "wb")
                        self.file_reception_registry[file_id]["file_handle"] = file_handle

                    file_handle = self.file_reception_registry[file_id]["file_handle"]
                    file_handle.write(plaintext_bytes)

                    if message["final"] == True: # TODO: [DONE] Clean up file handles, clear up memory
                        self._send_ack(message=message, file_id=file_id, final=True, status="ok")
                        print(f"FILE RECEIVED: {filename} at {self.file_dir}/{filename} from {message['alias']}")
                        file_handle.close()
                        self.file_reception_registry[file_id]["file_handle"] = None
                    else:
                        self._send_ack(message=message, file_id=file_id, final=False, status="ok")

            except Exception as e:
                print(f"Could not process received chunk packet. Error {e}")

        elif message["destination_id"] is not None:
            next_node = self._find_node(alias=message["recipient"])
            self._forward_message(next_node=next_node, message=message)

    def _handle_ack_message(self, message): # TODO [DONE] prep for seq mismatch, [DONE] destroy engine if final ACK
        if message["destination_id"] == str(self.node_id):
            decrypted_message = self._decrypt_message(message=message)

            file_id = decrypted_message["payload"]["file_id"]
            engine = self.sending_engine_registry[file_id]

            if decrypted_message["payload"]["status"] == "seq_mismatch":
                print(f"MISMATCHING SEQ DETECTED! FILE TRANSFER TO {message['alias']} CANCELLED.")
                engine.stop_sending.set()

            if decrypted_message["payload"]["final"] == True:
                print(f"FILE SUCCESSFULLY SENT: {message["payload"]["filename"]}.\nFINAL ACK MESSAGE RECEIVED, "
                      f"DESTROYING ENGINE WITH FILE ID {engine.file_uuid}")
                engine = None
                self.sending_engine_registry[file_id] = None

            engine.ack_received.set()
        else:
            next_node = self._find_node(alias=message["recipient"])
            self._forward_message(message=message, next_node=next_node)

    def _send_ack(self, message: dict, file_id: str, final: bool, status: str):

        ack_message = {
            "type": "ACK",
            "alias": message["recipient"],
            "recipient": message["alias"],
            "origin": "py_netmesh",
            "node_id": self.node_id,
            "destination_id": message["destination_id"],
            "ip": self.ip,
            "payload": {
                "seq": message["seq"],
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
            if recipient_dict[node_key]['hop_count'] == 1:

                recipient_pk = recipient_dict[node_key]["public_key"]

                encrypted_data = self._encrypt_message(payload=ack_message["payload"], public_key=recipient_pk)
                ack_message["payload"] = encrypted_data

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(json.dumps(ack_message).encode('utf-8'),
                            (recipient_dict[node_key]["ip"], recipient_dict[node_key]["port"]))
                sock.close()
                print(f"Ack message for chunk {message["seq"]} to {message['recipient']}!")
            else:
                next_hop = recipient_dict[node_key]["next_hop"]

                next_node = self._routing_table[next_hop]

                recipient_pk = recipient_dict[node_key]["public_key"]

                encrypted_data = self._encrypt_message(payload=message["payload"], public_key=recipient_pk)
                message["payload"] = encrypted_data

                self._forward_message(next_node=next_node, message=message)

    def _decrypt_message(self, message: dict):
        sender_id = message["node_id"]
        if sender_id in self._routing_table:
            sender_info = self._routing_table[sender_id]
            sender_public_key = sender_info["public_key"]

            # convert string back to bytes, remove b64 encoding
            # CHAT specific message signing verification
            if message["type"] == "CHAT":
                signature_bytes = base64.b64decode(message["signature"].encode('utf-8'))

                # stringify payload dict for verification
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

            # again, convert back into bytes and remove b64 encoding
            encrypted_payload_bytes = base64.b64decode(encrypted_payload_string.encode('utf-8'))

            plaintext_bytes = self._private_key_obj.decrypt(
                ciphertext=encrypted_payload_bytes,
                padding=padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # return decrypted bytes to string for final decoded message
            plaintext_string = plaintext_bytes.decode('utf-8')
            original_payload_dict = json.loads(
                plaintext_string)

            message["payload"] = original_payload_dict

            return message

        else:
            print(f"Sender not in routing table. Suspending decryption...")
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
            decrypted_bytes = aesgcm.decrypt(encrypted_payload, nonce, aad)
            plaintext_data = decrypted_bytes.decode('utf-8')
            plaintext_json = json.loads(plaintext_data)
            return plaintext_json

        except InvalidTag as e:
            print(f"Could not decrypt file chunk {seq}. Error {e}")
            return None

    def _sign(self, message: dict):
        payload = message["payload"]
        json_string = json.dumps(payload, sort_keys=True)  # convert json to string
        data_to_sign = json_string.encode('utf-8')  # serialize string into bytes for encryption

        # in its byte form, we create our salted signature
        signature = self._private_key_obj.sign(data_to_sign, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA256())

        # decode utf-8 = convert from bytes back into string. base64 ensures all bytes are converted into safe chars
        string_signature = base64.b64encode(signature).decode('utf8')
        message["signature"] = string_signature

    def _deserialize_pk(self, pk: str):
        received_pub_key_string = pk
        public_pem_data = received_pub_key_string.encode('utf-8')
        public_key_object = load_pem_public_key(public_pem_data)
        return public_key_object

    def _scan_for_routes(self, routing_table: dict, parent_id: str):
        for node in routing_table:
            if node == str(self.node_id):
                continue
            elif node not in self._routing_table:
                pk_object = self._deserialize_pk(routing_table[node]['public_key'])
                self._routing_table[node] = {
                    "alias": routing_table[node]["alias"],
                    "hop_count": int(routing_table[node]["hop_count"]) + 1,
                    "next_hop": parent_id,
                    "public_key": pk_object,
                }
                self.routes_to_send[node] = {
                    "alias": routing_table[node]["alias"],
                    "hop_count": int(routing_table[node]["hop_count"]) + 1,
                    "next_hop": parent_id,
                    "public_key": routing_table[node]["public_key"],
                }
                print(f"New node found via PROBE: {self._routing_table[node]['alias']}")
            else:
                if int(routing_table[node]["hop_count"]) < int(self._routing_table[node]["hop_count"]):
                    self._routing_table[node]["hop_count"] = int(self._routing_table[node]["hop_count"])
                    self._routing_table[node]["next_hop"] = parent_id
                else:
                    continue

    def _find_node(self, alias: str): # search until hop_count == 1
        for node, info, in self._routing_table.items():
            if info["alias"] == alias:
                node = self._routing_table[node]
                if node["hop_count"] == 1:
                    return node
                else:
                    node = self._routing_table[node["next_hop"]]
                    return node
        print(f"No node found for: {alias}")

    def make_file_dir(self):
        path = pathlib.Path("../py_netmesh_received_files")
        self.file_dir = path
        self.file_dir.mkdir(parents=True, exist_ok=True)

class Engine:
    def __init__(self):
        self.seq = 0
        self.chunk_num = 0
        self.file_uuid = None
        self.ack_received = threading.Event()
        self.stop_sending = threading.Event()
        self.chunk_queue = queue.Queue()
        self.recipient_dict = {}
        self._routing_table = {}
        self.recipient_id = None

    def start(self, id: str, filepath, message_data: dict):
        self.file_uuid = id
        chunk_processing = threading.Thread(target=self.process_chunks, args=(filepath, message_data),daemon=True)
        chunk_processing.start()
        return chunk_processing

    # How do we handle getting ACK messages? another queue? how do we feed specific ACKS to correct engine?
    # Event() that replaces the loop bool, waits for ack to send next chunk

    def process_chunks(self, filepath: str, message_data: dict):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.file_uuid = message_data["payload"]["file_id"]
        chunk_size = 1024 * 1024
        self.chunk_num = self.number_of_chunks(filepath=filepath, chunk_size=chunk_size)
        next_hop = self.find_next_hop()

        session_key = AESGCM.generate_key(256)
        public_key = message_data["recipient_pk"]
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

        while not self.stop_sending:
            for chunk in self.fetch_chunk(size=chunk_size, path=filepath):
                if self.stop_sending:
                    break
                data_to_send = deepcopy(message_data)
                data_to_send["session_key"] = session_key # add this after deepcopy to avoid PICKLING error
                data_to_send["seq"] = self.seq
                if data_to_send["seq"] == self.chunk_num:
                    data_to_send["final"] = True
                # TODO: [DONE] add event to fetch_chunk so it wakes up upon ack
                encrypted_chunk_data = self.encrypt_chunk(chunk, data_to_send, aesgcm)
                self.chunk_queue.put(encrypted_chunk_data)

                if self.seq > 0:
                    if not self.ack_received.wait(timeout=7.0):
                        print(f"Timed out waiting for ACK for chunk {self.seq - 1}")
                        break
                    self.ack_received.clear()

                self.send_chunk(next_hop=next_hop, sock=sock)

                if self.seq == 0: # have session key ONLY in first chunk
                    del message_data["session_key"]
                self.seq += 1

                # TODO: [DONE-handled in processor] add final wait after loop to ensure final chunk arrives

    def fetch_chunk(self, size: int, path: str):
        with open(file=path, mode="rb") as f:
            while True:
                chunk = f.read(size)
                if not chunk:
                    break
                yield chunk

    def send_chunk(self, next_hop, sock):
        # here we will pull from a queue, loaded in after the encrypt function below. Use Event() to send chunks relevant
        # to ACK responses.
        chunk_data = self.chunk_queue.get()
        json_string = json.dumps(chunk_data, sort_keys=True)
        json_bytes = json_string.encode('utf-8')

        sock.sendto(json_bytes, (next_hop["ip"], next_hop["port"]))

    def confirm_ack(self, ack_seq: int):
        sent_seq = self.seq - 1
        if sent_seq == ack_seq:
            self.ack_received.set()

    def encrypt_chunk(self, chunk, message_data: dict, aesgcm: AESGCM) -> dict:
        # we use HYBRID enc here, because RSA enc has size limit beneath our 1mb threshold.
        # we will first enc the chunks with AES Symm key, and then enc the AES key with our Assym RSA key, like w/ strings
        # send enc symm key to recipient, which they will open with their private key
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
        return file_size // chunk_size

# TODO(s) NEXT TIME: 1. (DONE) Serialize dict for network transmission 2. (DONE) create ack schema
#   3. (DONE) finish stop-and-wait implementation on sender-side. 4. (DONE) REMEMBER for recipient to save session key from
#   FIRST chunk