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
