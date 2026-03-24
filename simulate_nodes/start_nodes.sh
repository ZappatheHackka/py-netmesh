#!/bin/bash

read -p "How many nodes would you like to simulate? " node_num

for (( i = 1; i <= node_num; i +=1)); do
	gnome-terminal --title="Simulated Node $i" -- bash -c "cd ..; source .venv/bin/activate; python3 py_netmesh/cli.py start --port 500$i; exec bash"&
done


