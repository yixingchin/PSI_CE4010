import socket
from PSI_environment import *

class PSI_server:
	def __init__(self, env, length, port):
		if env is False:
			self.env = PSI_environment(length)
		else:
			self.env = env
		n, p, x, u = self.env.get_all()
		self.port = port
		self.moduli = n
		self.verification_exponent = p
		self.generator = x
		self.local_encryption_base = u
		self.client_dict = {}

	def listen(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind(("localhost", self.port))
		s.listen(1)
		while True:
			c, addr = s.accept()
			req = c.recv(1024)
			req = req.split("_".encode())
			if req[0] == b"SBS":
				self.client_dict[(req[1], req[2])] = req[3]
				c.send(("_".join([str(self.moduli),str(self.verification_exponent),str(self.generator),str(self.local_encryption_base)])).encode())
			if req[0] == b"QRY":
				c.send(self.client_dict[(req[1], req[2])])
			if req[0] == b"STP":
				c.close()
				s.close()
			c.close()