import socket
import threading
import time
import hashlib
import json
from urllib.parse import urlparse
import time


class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash

def calculate_hash(index, previous_hash, timestamp, data):
    value = str(index) + str(previous_hash) + str(timestamp) + str(data)
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def create_genesis_block():
    return Block(0, "0", time.time(), "Genesis Block", calculate_hash(0, "0", time.time(), "Genesis Block"))

def append_new_block(inde,previous_hash, data,timesta):
    index = inde
    timestamp = timesta
    hash_value = calculate_hash(index, previous_hash, timestamp, data)
    return Block(index, previous_hash, timestamp, data, hash_value)

def create_new_block(previous_block, data):
    index = previous_block.index + 1
    timestamp = time.time()
    hash_value = calculate_hash(index, previous_block.hash, timestamp, data)
    return Block(index, previous_block.hash, timestamp, data, hash_value)

class Blockchain:
    def __init__(self):
        self.chain = [create_genesis_block()]
        self.nodes = set()
        self.lock = threading.Lock()

    def get_last_block(self):
        return self.chain[-1]

    def validate_chain(self, remote_chain):
        return True

    def add_block(self, data):
        with self.lock:
            new_block = create_new_block(self.get_last_block(), data)
            self.chain.append(new_block)
            return new_block


    def add_node(self, address):
        parsed_url = urlparse(address)
        print(parsed_url)
        print(parsed_url.netloc)
        self.nodes.add(parsed_url.path)

    def connect_to_node(self, address):
        self.add_node(address)
        print(f"Connected to node at {address}")
        self.sync_nodes()

    def sync_nodes(self, target_node=None):
        for node in self.nodes:
            if target_node is not None and node != target_node:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((node, 12345))
                    s.sendall(json.dumps({'type': 'sync', 'chain': [block.__dict__ for block in self.chain]}).encode('utf-8'))
            except socket.error as e:
                print(f"Failed to sync with node {node}: {e}")
                if e.errno == 10049:
                    print("Check if the IP address and port are correct.")
                elif e.errno == 10061:
                    print("Connection refused. Make sure the node is running and the port is open.")


blockchain = Blockchain()

def handle_client(conn, addr):
    with conn:
        while True:
            data = conn.recv(1024).decode('utf-8')
            #print(data)
            if not data:
                break
            message = json.loads(data)

            if message['type'] == 'mine':
                data = message['data']
                new_block = blockchain.add_block(data)
                blockchain.sync_nodes()
                response = {'message': 'Block mined successfully', 'block': new_block.__dict__}
                conn.sendall(json.dumps(response).encode('utf-8'))

            elif message['type'] == 'sync':
                remote_chain = message['chain']
                if len(remote_chain) > len(blockchain.chain) and blockchain.validate_chain(remote_chain):
                    og_bc = len(blockchain.chain)
                    rc_bc = len(remote_chain)
                    excess_blks = remote_chain[og_bc:]
                    for blks in excess_blks:
                        ine = blks['index']
                        data = blks['data']
                        pre_hash =blks['previous_hash']
                        ts = blks['timestamp']
                        new_block = append_new_block(inde=ine,previous_hash=pre_hash,data=data,timesta=ts)
                        blockchain.chain.append(new_block)
                        blockchain.sync_nodes()
                print(f"Synchronized with {addr[0]}:{addr[1]}")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('', 12346))
        server.listen(5)
        print("[*] Server listening on port 5001")
        while True:
            conn, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
            client_handler = threading.Thread(target=handle_client, args=(conn, addr))
            client_handler.start()

def start_miner():
    data = input("Enter your transaction data: ")
    blockchain.add_block(data)
    blockchain.sync_nodes()

def start_node():
    address = input("Enter node address to connect (e.g., localhost:5001): ")
    address = str(address)
    blockchain.connect_to_node(address)

def display_blocks():
    for block in blockchain.chain:
        print(block.index)
        print(block.data)
        print(block.timestamp)
        print("----------------------------------------------")
if __name__ == '__main__':
    server_thread = threading.Thread(target=start_server)
    server_thread.start()
    while(True):
        print("1.Transaction")
        print("2.Add Node")
        print("3.Display blocks")
        option = int(input("Enter the choice:"))
        if option == 1:
            start_miner()
        elif option == 2:
            start_node()
        elif option == 3:
            display_blocks()
        else:
            print("Wrong Option Selected retry!!")
