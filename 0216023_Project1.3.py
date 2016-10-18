import socket
import sys
import struct
# The following libraries should be installed before executing
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Construct a TCP socket
HOST, PORT = "140.113.194.88", 45000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
	# Connect to the server
	sock.connect((HOST, PORT))
	
	# Send hello to server
	# 1. Send the size in byte of "hello" to Server
	msg_size = len("hello")
	byte_msg_size = struct.pack("i", msg_size)
	sock.sendall( byte_msg_size )
	# 2. Send the "hello" string to Server
	sock.sendall(bytes("hello", 'utf-8'))
	print('I send : hello')

	# Receive hello from server
	msg_size = struct.unpack('i', sock.recv(4))
	received = str(sock.recv(int(msg_size[0])), "utf-8")
	print('TA send : ', received)