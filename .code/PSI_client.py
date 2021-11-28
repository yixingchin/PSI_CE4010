from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
import numpy as np
import socket
from PSI_client_util import *

class PSI_client:
	def __init__(self, port, server_ip, server_port, rand_length=128, bin_bit_length=6):
		self.local_port = port
		self.server_ip = server_ip
		self.server_port = server_port

		self.pri_key = RSA.generate(1024)
		self.pub_key = self.pri_key.publickey()

		moduli, v_exp, gen, local_enc_base = self.subscribe_server()
		self.c_util = PSI_client_util(int(moduli.decode()), int(v_exp.decode()), int(gen.decode()), rand_length)

		self.moduli = int(moduli.decode())
		self.local_enc_base = int(local_enc_base.decode())

		self.element_list = []
		self.enc_element_list = []
		self.bins = []

		self.rand_length = rand_length
		self.bin_bit_length = bin_bit_length	# e.g. bin_bit_length = 3 means there are 8 bins

		self.hash_history = {}
		self.inv_perm = []

		self.session_key = 0
		self.ctx_buffer = []

		self.intersection = []

	def zip(self, l):
		ret = ""
		for i in range(len(l)):
			l[i] = str(l[i])
		return "_".join(l)
			

	def unzip(self,s):
		l = s.split("_")
		ret = []
		for e in l:
			e = int(e)
			ret.append(e)
		return ret


	def apply_signature(self, ctx):
		ctx = str(ctx)
		h = SHA256.new(ctx.encode())
		signature = PKCS1_v1_5.new(self.pri_key).sign(h)
		'''
		print("apply:")
		print(ctx)
		print(signature)
		'''
		return (ctx+"____").encode() + signature

	def test_signature(self, ctx, peer_pub_key):
		ctx = ctx.split("____".encode())
		ctx, signature = ctx[0], ctx[1]
		h = SHA256.new(ctx)
		isValid = PKCS1_v1_5.new(peer_pub_key).verify(h, signature)
		'''
		print("test:")
		print(ctx.decode())
		print(signature)
		'''
		if not isValid:
			return False
		return int(ctx.decode())

	def AES_encrypt(self, ctx):
		key = str(self.session_key)[:32]
		iv = Random.new().read(AES.block_size)
		ctx = AES.new(key.encode(), AES.MODE_CFB, iv).encrypt(ctx.encode())
		return (ctx.hex()+iv.hex()).encode()

	def AES_decrypt(self, ctx):
		ctx = ctx.decode()
		iv = bytes.fromhex(ctx[-32:])
		ctx = bytes.fromhex(ctx[:-32])
		key = str(self.session_key)[:32]
		ctx = AES.new(key.encode(), AES.MODE_CFB, iv).decrypt(ctx)
		return ctx.decode()

	
	def subscribe_server(self):
		c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		c.connect((self.server_ip, self.server_port))
		c.send(("SBS_"+"127.0.0.1"+"_"+str(self.local_port)+"_"+self.pub_key.exportKey().decode()).encode())
		param = c.recv(1024).split("_".encode())
		c.close()
		return param[0], param[1], param[2], param[3]

	def query_public_key(self, peer_ip, peer_port):
		c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		c.connect((self.server_ip, self.server_port))
		c.send(("QRY_"+peer_ip+"_"+str(peer_port)).encode())
		peer_pub_key = c.recv(1024)
		c.close()
		return RSA.importKey(peer_pub_key)

	def request_intersect(self, peer_ip, peer_port):
		peer_pub_key = self.query_public_key(peer_ip, peer_port)

		#Initialize as a client in TCP model
		c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		c.connect((peer_ip, peer_port))

		#Get the first context
		ctx = self.c_util.session_key()

		#Apply PKC1_v1_5 and get its signature
		ctx = self.apply_signature(ctx)

		c.send(ctx)													# CLIENT -> server, COMM 1

		ctx = c.recv(1024)											# server -> CLIENT, COMM 1

		#Test for signature
		ctx = self.test_signature(ctx, peer_pub_key)
		if not ctx:
			print("Invalid signature")
			return

		self.session_key = self.c_util.session_key_ack(ctx)

	#----------------ROUND 0 DONE----------------

		for i in range(len(self.bins)):
			self.c_util.load(self.bins[i])

			ctx = self.c_util.round_one()
			c.send(self.AES_encrypt(self.zip(ctx)))					# CLIENT -> server, COMM 2
			ctx = self.unzip(self.AES_decrypt(c.recv(1024)))		# server -> CLIENT, COMM 2
			self.c_util.round_one_ack(ctx)

			ctx = self.c_util.round_two()
			c.send(self.AES_encrypt(self.zip(ctx)))					# CLIENT -> server, COMM 3
			ctx = self.unzip(self.AES_decrypt(c.recv(1024)))		# server -> CLIENT, COMM 3
			ret = self.c_util.round_two_ack(ctx)
			'''
			if ret is False:
				print("Invalid message")
				return
			'''
			self.find_intersection(ret, i)
			#self.c_util.new_md()

		c.close()
				


	def listen(self, peer_ip, peer_port):

		#Initialze as a server in TCP model
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind(("127.0.0.1", self.local_port))
		s.listen(1)
		c, addr = s.accept()

		ctx = c.recv(1024)											# client -> SERVER, COMM 1
		peer_pub_key = self.query_public_key(peer_ip, peer_port)

		#Test for signature
		ctx = self.test_signature(ctx, peer_pub_key)
		if not ctx:
			print("Invalid signature")
			return
		self.session_key = self.c_util.session_key_ack(ctx)

		#Get the first context
		ctx = self.c_util.session_key()

		#Apply PKC1_v1_5 and get its signature
		ctx = self.apply_signature(ctx)

		c.send(ctx)													# SERVER -> client, COMM 1

	#----------------ROUND 0 DONE----------------

		for i in range(len(self.bins)):
			self.c_util.load(self.bins[i])

			ctx = self.unzip(self.AES_decrypt(c.recv(1024)))		# client -> SERVER, COMM 2
			self.c_util.round_one_ack(ctx)
			ctx = self.c_util.round_one()
			c.send(self.AES_encrypt(self.zip(ctx)))					# SERVER -> client, COMM 2

			ctx = self.unzip(self.AES_decrypt(c.recv(1024)))		# client -> SERVER, COMM 3
			ret = self.c_util.round_two_ack(ctx)
			'''
			if ret is False:
				print("Invalid message")
				print(i, ctx)
				return
			'''
			ctx = self.c_util.round_two()
			c.send(self.AES_encrypt(self.zip(ctx)))					# SERVER -> client, COMM 3

			self.find_intersection(ret, i)
			#self.c_util.new_md()

		c.close()
		s.close()


	def find_intersection(self, ret, i):
		inv_p = self.inv_perm[i]
		for e in ret:
			if (i, inv_p[e]) in self.hash_history.keys():
				self.intersection.append(self.hash_history[(i, inv_p[e])])


	def prepare(self, element_list):
		self.intersection = []
		self.bins = []
		self.hash_history = {}
		self.inv_perm = []
		self.load_list(element_list)
		self.divide()
		self.permutate_bin()

	def load_list(self, element_list):
		self.element_list = element_list
		self.enc_element_list = []
		for e in element_list:
			self.enc_element_list.append(pow(self.local_enc_base, (e+1), self.moduli))
		
	def generate_dummy_element(self):
		return pow(self.local_enc_base, number.getRandomInteger(self.rand_length), self.moduli)
	
	def divide(self):

		l = pow(2,self.bin_bit_length)
		for i in range(l):
			self.bins.append([])
		for i in range(len(self.element_list)):
			e = self.element_list[i]
			h = SHA256.new()
			h.update(str(e).encode("utf-8"))
			b = int(bin(int(h.hexdigest(),16))[-self.bin_bit_length:],2)
			self.bins[b].append(self.enc_element_list[i])
			self.hash_history[(b, len(self.bins[b])-1)] = self.element_list[i]
		
	def permutate_bin(self):
		l = pow(2,self.bin_bit_length)
		max_len = 0
		for b in self.bins:
			max_len = max(max_len, len(b))
		for b in self.bins:
			for n in range(max_len-len(b)):
				b.append(self.generate_dummy_element())
		for j in range(len(self.bins)):
			b = self.bins[j]
			p = np.random.permutation(max_len)
			inv_p = []
			for i in p:
				inv_p.append(0)
			for i in p:
				inv_p[p[i]] = i
			self.inv_perm.append(inv_p)
			q = []
			for n in range(max_len):
				q.append(0)
			for n in range(max_len):
				q[p[n]] = b[n]
			self.bins[j] = q
