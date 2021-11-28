from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random

class PSI_client_util:
	def __init__(self, moduli, v_exp, gen, rand_length):

		m_enc_exp = number.getRandomInteger(rand_length)
		d_enc_exp = number.getRandomInteger(rand_length)
		self.rand_length = rand_length
		
		#Parameters of the encryption environment, taken in from constructer call
		self.moduli = moduli #n
		self.v_exp = v_exp #p
		self.gen = gen #x

		#Client specific parameters
		self.m_enc_exp = m_enc_exp #m
		self.d_enc_exp = d_enc_exp #d

		#An instance acts as if naively intersecting two lists
		self.enc_element_list = []

		self.s_key = 0
		self.ctx_buffer = []

	def new_md(self):
		self.m_enc_exp = number.getRandomInteger(self.rand_length)
		self.d_enc_exp = number.getRandomInteger(self.rand_length)

	def load(self, l):
		self.enc_element_list = l

	def session_key(self):
		x = self.gen
		m = self.m_enc_exp
		n = self.moduli
		
		x_pow = pow(x, m, n)
		return x_pow
	
	def session_key_ack(self, ctx):
		m = self.m_enc_exp
		n = self.moduli
		x_pow = ctx
		self.s_key = pow(x_pow, m, n)
		return self.s_key
	
	def round_one(self):
		m = self.m_enc_exp
		d = self.d_enc_exp
		x = self.gen
		n = self.moduli
		x_pow = pow(x, m, n)
		
		ctx = []
		b = self.enc_element_list
		for i in b:
			s_pow = pow(i, m, n)
			sx_pow_d = pow(s_pow*x_pow, d, n)
			ctx.append(s_pow)
			ctx.append(sx_pow_d)
		return ctx
	
	def round_one_ack(self, ctx):
		self.ctx_buffer = ctx
		
	def round_two(self):
		m = self.m_enc_exp
		n = self.moduli
		buffer = self.ctx_buffer
		
		ctx = []
		for i in self.ctx_buffer:
			ctx.append(pow(i, m, n))
		return ctx
	
	def round_two_ack(self,ctx):
		s = self.s_key
		d = self.d_enc_exp
		m = self.m_enc_exp
		n = self.moduli
		p = self.v_exp
		buffer = self.ctx_buffer
		flag = True

		for i in range(0, len(ctx),2):
			k = ctx[i]
			l = ctx[i+1]
			if pow(k*s, d, n) != l or pow(k, p, n) != 1:
				flag = False
				break
		if not flag:
			return False
		ret = []
		for i in range(0, len(ctx), 2):
			for j in range(0, len(buffer), 2):
				if ctx[i] == pow(buffer[j], m, n):
					ret.append(int(i/2))
		return ret

























































		
	def match_generate_r1_ctx(self):
		s = self.enc_single_element
		m = self.m_enc_exp
		d = self.d_enc_exp
		x = self.gen
		n = self.moduli
		s_pow = pow(s, m, n)
		x_pow = pow(x, m, n)
		ctx = [s_pow, x_pow, pow((s_pow*x_pow)%n, d, n)]
		string = ""
		for i in ctx:
			string = string + str(i) + "_"
		h = SHA256.new(string.encode("utf-8"))
		signature = PKCS1_v1_5.new(self.sig_key).sign(h)
		ctx.append(signature)
		return ctx
	
	def match_check_r1_ctx(self, pub_key, ctx):
		signature = ctx[3]
		ctx = ctx[:3]
		string = ""
		for i in ctx:
			string = string + str(i) + "_"
		h = SHA256.new(string.encode("utf-8"))
		return PKCS1_v1_5.new(pub_key).verify(h, signature)
	
	def match_generate_r2_ctx(self):
		m = self.m_enc_exp
		n = self.moduli
		buffer = self.ctx_buffer
		ctx = str(pow(buffer[0], m, n))+ "_" + str(pow(buffer[1], m, n))
		key = str(self.session_key)[:32]
		iv = Random.new().read(AES.block_size)
		ctx = AES.new(key, AES.MODE_CFB, iv).encrypt(ctx)
		return [ctx, iv]
	
	def match_decrypt_r2_ctx(self, ctx):
		iv = ctx[1]
		ctx = ctx[0]
		key = str(self.session_key)[:32]
		ctx = AES.new(key, AES.MODE_CFB, iv).decrypt(ctx)
		ctx = ctx.split("_".encode())
		ctx = [int(ctx[0]), int(ctx[1])]
		return ctx
	
	def match_check_r2_ctx(self, ctx):
		k = ctx[0]
		l = ctx[1]
		s = self.session_key
		d = self.d_enc_exp
		n = self.moduli
		v = self.v_exp
		return (pow((k*s)%n, d, n) == l and pow(k, v, n) == 1)

	
	
	
	def match_r1(self, peer):
		ctx = self.match_generate_r1_ctx()
		peer.match_r1_reply(self, ctx)
		
	def match_r1_reply(self, peer, ctx):
		pub_key = self.env.get_pub_key(peer)
		if not self.match_check_r1_ctx(pub_key, ctx):
			print("Signature check failed, from " + self.name)
			return
		self.session_key = pow(ctx[1], self.m_enc_exp, self.moduli)
		self.ctx_buffer = [ctx[0], ctx[2]]
		
		ctx = self.match_generate_r1_ctx()
		peer.match_r2(self, ctx)
	
	def match_r2(self, peer, ctx):
		pub_key = self.env.get_pub_key(peer)
		if not self.match_check_r1_ctx(pub_key, ctx):
			print("Signature check failed, from " + self.name)
			return
		self.session_key = pow(ctx[1], self.m_enc_exp, self.moduli)
		self.ctx_buffer = [ctx[0], ctx[2]]
		
		ctx = self.match_generate_r2_ctx()
		peer.match_r2_reply(self, ctx)
	
	def match_r2_reply(self, peer, ctx):
		ctx = self.match_decrypt_r2_ctx(ctx)
		if not self.match_check_r2_ctx(ctx):
			print("Message integrity check failed, from " + self.name)
			return
		if ctx[0] == pow(self.ctx_buffer[0], self.m_enc_exp, self.moduli):
			self.intersection.append(self.single_element)
		
		ctx = self.match_generate_r2_ctx()
		peer.match_finish(self, ctx)
		
	def match_finish(self, peer, ctx):
		ctx = self.match_decrypt_r2_ctx(ctx)
		if not self.match_check_r2_ctx(ctx):
			print("Message integrity check failed, from " + self.name)
			return
		if ctx[0] == pow(self.ctx_buffer[0], self.m_enc_exp, self.moduli):
			self.intersection.append(self.single_element)
		