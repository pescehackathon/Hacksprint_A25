import socket
import threading
import time
import hashlib
import json
import rsa
from urllib.parse import urlparse

class Wallet:
    def __init__(self):
        self.public_key, self.private_key = rsa.newkeys(512)

class User:
    def __init__(self, username, wallet, initial_balance):
        self.username = username
        self.wallet = wallet
        self.balance = initial_balance

class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash, signature=None, public_key=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash
        self.signature = signature
        self.public_key = public_key

def calculate_hash(index, previous_hash, timestamp, data):
    value = str(index) + str(previous_hash) + str(timestamp) + str(data)
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def create_genesis_block(wallet):
    return Block(0, "0", time.time(), "Genesis Block", calculate_hash(0, "0", time.time(), "Genesis Block"))

def append_new_block(wallet, inde, previous_hash, data, timesta):
    index = inde
    timestamp = timesta
    hash_value = calculate_hash(index, previous_hash, timestamp, data)
    signature = wallet.sign_transaction(hash_value)
    return Block(index, previous_hash, timestamp, data, hash_value, signature, wallet.public_key)

def create_new_block(wallet, previous_block, data):
    index = previous_block.index + 1
    timestamp = time.time()
    hash_value = calculate_hash(index, previous_block.hash, timestamp, data)
    signature = wallet.sign_transaction(hash_value)
    return Block(index, previous_block.hash, timestamp, data, hash_value, signature, wallet.public_key)

class Blockchain:
    def __init__(self):
        self.chain = [create_genesis_block(Wallet())]
        self.nodes = set()
        self.lock = threading.Lock()
        self.balances = {}
        self.users = {}

    def get_last_block(self):
        return self.chain[-1]

    def validate_chain(self, remote_chain):
        return True

    def add_block(self, wallet, data):
        with self.lock:
            new_block = create_new_block(wallet, self.get_last_block(), data)
            self.chain.append(new_block)
            self.update_balances(new_block)
            return new_block

    def add_user(self, username, initial_balance):
        new_wallet = Wallet()
        new_user = User(username, new_wallet, initial_balance)
        self.users[username] = new_user
        self.balances[username] = initial_balance

    def update_balances(self, block):
        for transaction in block.data.split(";"):
            sender, recipient, amount = transaction.split(":")
            amount = float(amount)
            self.balances[sender] -= amount
            self.balances[recipient] += amount

    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

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

def handle_client(conn, addr, wallet, blockchain):
    with conn:
        while True:
            data = conn.recv(1024).decode('utf-8')
            if not data:
                break
            message = json.loads(data)

            if message['type'] == 'mine':
                data = message['data']
                new_block = blockchain.add_block(wallet, data)
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
                        inde = blks['index']
                        data = blks['data']
                        pre_hash = blks['previous_hash']
                        ts = blks['timestamp']
                        new_block = append_new_block(wallet, inde=inde, previous_hash=pre_hash, data=data, timesta=ts)
                        blockchain.chain.append(new_block)
                        blockchain.update_balances(new_block)
                    print(f"Synchronized with {addr[0]}:{addr[1]}")

def start_server(wallet, blockchain):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('', 12345))
        server.listen(5)
        print("[*] Server listening on port 12345")
        while True:
            conn, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
            client_handler = threading.Thread(target=handle_client, args=(conn, addr, wallet, blockchain))
            client_handler.start()

def start_miner(wallet, blockchain):
    data = input("Enter your transaction data (e.g., sender:recipient:amount): ")
    blockchain.add_block(wallet, data)
    blockchain.sync_nodes()

def start_node(blockchain):
    address = input("Enter node address to connect (e.g., localhost:12345): ")
    address = str(address)
    blockchain.connect_to_node(address)

def display_blocks(blockchain):
    for block in blockchain.chain:
        print("Block Index:", block.index)
        print("Previous Hash:", block.previous_hash)
        print("Timestamp:", block.timestamp)
        print("Data:", block.data)
        print("Hash:", block.hash)
        print("Signature:", block.signature)
        print("Public Key:", block.public_key)
        print("----------------------------------------------")

def display_balances(blockchain):
    print("User Balances:")
    for user, balance in blockchain.balances.items():
        print(f"{user}: {balance}")

def add_user(blockchain):
    username = input("Enter new username: ")
    initial_balance = float(input("Enter initial balance: "))
    blockchain.add_user(username, initial_balance)
    print(f"User '{username}' added with initial balance {initial_balance}")

if __name__ == '__main__':
    wallet = Wallet()
    blockchain = Blockchain()

    server_thread = threading.Thread(target=start_server, args=(wallet, blockchain))
    server_thread.start()

    while True:
        print("1. Mine Block")
        print("2. Add Node")
        print("3. Display Blocks")
        print("4. Display Balances")
        print("5. Add User")
        option = int(input("Enter the choice: "))

        if option == 1:
            start_miner(wallet, blockchain)
        elif option == 2:
            start_node(blockchain)
        elif option == 3:
            display_blocks(blockchain)
        elif option == 4:
            display_balances(blockchain)
        elif option == 5:
            add_user(blockchain)
        else:
            print("Wrong Option Selected. Retry!!")
