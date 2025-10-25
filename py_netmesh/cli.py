from netmesh_py import Node
import argparse

def main():
    parser = argparse.ArgumentParser(prog="netmesh_py", description="netmesh_py CLI,"
                                                                    "a simple and robust mesh network library")
    subparsers = parser.add_subparsers(dest="command", required=True, help="netmesh_py commands")

    start_parser = subparsers.add_parser("start", help="start netmesh_py")
    start_parser.add_argument("--port", type=int, default=50000, help="port")
    start_parser.add_argument("--ip", type=str, default="127.0.0.1", help="ip address")
    start_parser.add_argument("--send", type=str, help="send a message")
    start_parser.add_argument("--list-neighbors", type=str, help="list all found neighbors")

    args = parser.parse_args()

    if args.command == "start":
        node = Node(args.ip, args.port)
        node.start()

        if args.command == "list-neighbors":
            print(node.neighbors)
        if args.command == "send":
            pass