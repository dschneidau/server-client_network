import socket
import json
import rsa
from binascii import hexlify
import os
import threading
import sys

# Define a client class
class Client:
	# Define some constants
	disconnect_request = ".exit" # Constant used to signal disconnection
	hash_method = "MD5" # Hash method used for digital signature

	# Constructor for the client class
	def __init__(self, address, username):
		self.address = address # Address of the server
		self.username = username # Username of the client
		self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a socket object
		self.active_users = {} # Dictionary to keep track of active users
		self.first_update = True
		self.generate_key() # Generate RSA keys for the user


	# Function to generate RSA keys for the user
	def generate_key(self):
		try:
			# Try to load the private key from a file
			with open(f'{self.username}/priv.key', 'rb') as f:
				priv_file_content = f.read()
			self.privkey = rsa.PrivateKey.load_pkcs1(priv_file_content)
		except IOError:
			# If the file doesn't exist, create a new keypair and save it to files
			os.mkdir(self.username)
			(self.pubkey, self.privkey) = rsa.newkeys(512)
			with open(f'{self.username}/pub.key', 'wb') as f:
				f.write(self.pubkey.save_pkcs1())
			with open(f'{self.username}/priv.key', 'wb') as f:
				f.write(self.privkey.save_pkcs1())
		finally:
			# Load the public key from a file
			with open(f'{self.username}/pub.key', 'rb') as f:
				pub_file_content = f.read()
			self.pubkey = pub_file_content.decode()

	# Function to generate digital signature for a message
	def digital_signature(self, msg):
		sign = rsa.sign(msg, self.privkey, self.hash_method)
		return sign.hex() # Return the signature as a hex string

	# Function to verify digital signature for a message
	def verify_sign(self, msg, sign, sender):
		pubkey_send = rsa.key.PublicKey.load_pkcs1(self.active_users[sender])
		try:
			used_hash = rsa.verify(msg, bytes.fromhex(sign), pubkey_send)
			return True
		except rsa.VerificationError:
			return False

	# Function to signal disconnection to the server
	def disconnection(self):
		data = {"sender": self.username, "receiver": "disconnect", "msg": self.disconnect_request}
		self.client.send(json.dumps(data).encode())

	# Function to send a broadcast message to all active users
	def send_broadcast(self, msg):
		for receiver in self.active_users:
			self.send(receiver, msg)

	# Function to send an encrypted message to a specific user
	def send(self, receiver, msg):
		pubkey_recv = rsa.key.PublicKey.load_pkcs1(self.active_users[receiver])
		crypto = rsa.encrypt(msg, pubkey_recv)
		data = {"sender": self.username, "receiver": receiver, "msg": crypto.hex(), "sign": self.digital_signature(msg)}
		self.client.send(json.dumps(data).encode())

	# Function to update the list of active users
	def update_users(self, users):
		if self.first_update:
			userlist= list(users.keys())
			self.username = userlist[-1]
			print(f'Your username is {self.username}')
			self.first_update = False
		del users[self.username]
		self.active_users = users
		print(f' Other Users: {list(self.active_users.keys())}. \n Enter Message Below')

	# Function to initialize the client by sending its username and public key to the server
	def init_data(self):
		data = {"username": self.username, "pubkey": self.pubkey}
		self.client.send(json.dumps(data).encode())


	# Function to listen for incoming messages from the client
	def listen(self):
		# Initialize data
		self.init_data()
		# Continuously listen for incoming messages
		try:
			while True:

				# Receive data from client in chunks of 1024 bytes and decode it as a JSON object
				data = self.client.recv(1024).decode()
				data = json.loads(data)
				# If the received data contains information about active users, update the list of active users
				if "users" in data.keys():
					self.update_users(data["users"])
				# Otherwise, the received data is a message from a user
				else:
					# Decrypt the message using the private key
					crypto = bytes.fromhex(data["msg"])
					msg = rsa.decrypt(crypto, self.privkey).decode()
					# Verify the signature on the message
					if self.verify_sign(msg.encode(), data["sign"], data["sender"]):
						# Print the message to the console
						print(f"\n {data['sender']}: {msg} \nMessage: ", end="")
		except json.decoder.JSONDecodeError:
			print('Left Server')
			exit()

		

	# Function to establish a connection to the client and send and receive messages
	def run(self):
		try:
			# Connect to the client
			print(f"Starting connection to {address}")
			self.client.connect(self.address)
			# Start a separate thread to listen for incoming messages
			thread = threading.Thread(target=self.listen)
			thread.start()
			# Continuously prompt the user for messages to send to other users
			while True:
				msg = input("Message: ")
				# If the user wants to disconnect, break out of the loop
				if msg == self.disconnect_request:
					self.disconnection()
					break
				# Determine the recipients of the message
				recipients = []
				for username in self.active_users:
					if '@'+username in msg:
						recipients.append(username)
				if not recipients:
					recipients = list(self.active_users.keys())
				# Send the message to each recipient
				for receiver in recipients:
					self.send(receiver, msg.encode())
		except:
			pass
		


IP = socket.gethostbyname(socket.gethostname())
PORT = 8000
address = (IP, PORT)

username = input("Insert username: ")
client = Client(address, username)
client.run()
