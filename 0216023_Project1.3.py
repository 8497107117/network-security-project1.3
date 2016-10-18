import socket
import sys
import struct
# The following libraries should be installed before executing
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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

	# Send public pem file to server
	with open('public.pem', 'rb') as f:
		myPubKey = serialization.load_pem_public_key(
			f.read(),
			backend=default_backend()
		)
		f.close()
	myPubPem = myPubKey.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)
	msg_size = len(str(myPubPem, 'utf-8'))
	byte_msg_size = struct.pack('i', msg_size)
	sock.sendall(byte_msg_size)
	sock.sendall(myPubPem)
	print('I send my RSA public key :\n', str(myPubPem, 'utf-8'))

	# Receive AES Session Key from server
	msg_size = struct.unpack('i', sock.recv(4))
	encryptedAESKey = sock.recv(int(msg_size[0]))
	print('Received C1 :\n', encryptedAESKey)
	with open('private.pem', 'rb') as f:
		myPriKey = serialization.load_pem_private_key(
			f.read(),
			password=None, 
			backend=default_backend()
		)
		f.close()
	AESKey = myPriKey.decrypt(
	    encryptedAESKey,
	    padding.OAEP(
	        mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
	        label=None
	    )
	)
	print('ASS Session Key :\n', AESKey)

	# Receive Initial Vector from Server
	msg_size = struct.unpack('i', sock.recv(4))
	encryptedIV = sock.recv(int(msg_size[0]))
	print('Received C2 :\n', encryptedIV)
	IV = myPriKey.decrypt(
	    encryptedIV,
	    padding.OAEP(
	        mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
	        label=None
	    )
	)
	print('Initial Vector :\n', IV)

	# Send my encrypted ID to server
	cipher = Cipher(algorithms.AES(AESKey), modes.CBC(IV), backend=default_backend())
	encryptor = cipher.encryptor()
	encryptedID = encryptor.update(b'0216023\0\0\0\0\0\0\0\0\0') + encryptor.finalize()
	msg_size = len(str(encryptedID))
	byte_msg_size = struct.pack('i', msg_size)
	sock.sendall(byte_msg_size)
	sock.sendall(encryptedID)
	print('Send my encrypted ID :\n', encryptedID)
	
	# Receive Magic Number from server
	msg_size = struct.unpack('i', sock.recv(4))
	encryptedMagicNum = sock.recv(int(msg_size[0]))
	print('Received C4 :\n', encryptedMagicNum)
	decryptor = cipher.decryptor()
	print('My Magic Number:\n', decryptor.update(encryptedMagicNum) + decryptor.finalize())

	# bye
	msg_size = struct.unpack("i", sock.recv(4))
	received = str(sock.recv(int(msg_size[0])), "utf-8")
	print(received)
