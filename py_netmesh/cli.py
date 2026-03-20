from core import Node
import argparse

def main():
    parser = argparse.ArgumentParser(prog="py_netmesh", description="py_netmesh CLI,"
                                                                    "a simple and robust mesh network library")
    subparsers = parser.add_subparsers(dest="command", required=True, help="py_netmesh commands")

    start_parser = subparsers.add_parser("start", help="start py_netmesh")
    start_parser.add_argument("--port", type=int, default=50000, help="port")
    start_parser.add_argument("--ip", type=str, default="127.0.0.1", help="ip address")
    start_parser.add_argument("--test", default=False, action="store_true",
                              help="runs on localhost for testing")

    args = parser.parse_args()

    if args.command == "start":
        node = Node(args.ip, args.port, args.test)
        node.start()

if __name__ == "__main__":
    main()