from netmesh_py import Node
import time

node = Node('127.0.0.1', 50000)
node.start()

try:
    while True:
        time.sleep(1)
        print("Discovered nodes: ", node.neighbors)
except KeyboardInterrupt:
    node.stop()