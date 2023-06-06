import socket
import json
import threading
import sys
import time
import random

class Server:
    def __init__(self, ADDR):

        self.ADDR = ADDR
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create a socket object
        try:
            self.server.bind(ADDR)  # bind socket to a specific address
        except OSError:
            print('Address already in use, please wait and try again')
            quit()
        self.active_users = {}  # dictionary to keep track of active users and their public keys

    def send_list_active_users(self):
        # create a dictionary with usernames as keys and public keys as values
        user_info = {user: self.active_users[user][1] for user in self.active_users}
        # create a dictionary with the key "users" and the value being the user_info dictionary
        users = {"users": user_info}
        # send the users dictionary to all active users
        for user, info in self.active_users.items():
            info[0].send(json.dumps(users).encode())

    def send_message(self, receiver, msg, sender, sign):
        # create a dictionary with the message sender, message content, and the digital signature
        data = {"sender": sender, "msg": msg, "sign": sign}
        # get the connection socket for the intended receiver of the message
        conn = self.active_users[receiver][0]
        # send the message dictionary to the receiver
        conn.send(json.dumps(data).encode())

    def disconnect_client(self, username, client):
        print(f"DISCONNECTING {username}")
        client.send("DISCONNECTING".encode())  # send a message to the client that they are being disconnected
        client.close()  # close the client's connection socket
        del self.active_users[username]  # remove the client from the active_users dictionary
        self.send_list_active_users()  # send the updated list of active users to all remaining active users

    def init_data(self, client):
        # receive data from the client, which should contain the client's username and public key
        data = client.recv(1024).decode()
        data = json.loads(data)
        # add the client's username and public key to the active_users dictionary
        random_number = str(random.randint(1, 99))
        while data["username"] + random_number in self.active_users:
            random_number = str(random.randint(1, 99))
        data["username"] += random_number
        self.active_users[data["username"]] = [client, data["pubkey"]]
        # send the updated list of active users to all active users
        self.send_list_active_users()
        return data["username"]

    def listen_client(self, conn, addr):
        # get the client's username
        username = self.init_data(conn)
        try:
            while True:
                # receive a message from the client
                msg = conn.recv(1024).decode()
                data = json.loads(msg)
                if data["msg"] == ".exit":
                    # if the client sends a disconnect message, disconnect them
                    self.disconnect_client(username, conn)
                else:
                    # if the client sends a regular message, send it to the intended receiver
                    print(f"[MESSAGE] {data}")
                    self.send_message(data["receiver"], data["msg"], data["sender"], data["sign"])
        except OSError:
            print('Client Disconected')
        except json.decoder.JSONDecodeError:
            print('Client Disconected Badly')
            self.disconnect_client(username, conn)


    def run(self):
        print("[STARTING] server is starting...")
        # start listening for incoming connections
        self.server.listen()
        print(f"[LISTENING] Server is listening on {ADDR}")
        while True:
            # accept incoming connections
            conn, addr = self.server.accept()
            # create a new thread to listen for messages from the new connection
            thread = threading.Thread(target=self.listen_client, args=(conn, addr))
            thread.start()
            time.sleep(1)
            # print the number of active connections and list of active users
            print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")
            print(f"[USERS] {list(self.active_users.keys())}")
		


IP = socket.gethostbyname(socket.gethostname())
PORT = 8000
ADDR = (IP, PORT)

server = Server(ADDR)
server.run()