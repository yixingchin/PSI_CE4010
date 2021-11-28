from Crypto.Util import number

class PSI_environment:
	def __init__(self, length):
		i, j = 0, 0
		while(True):
			i += 1
			p = number.getPrime(length)
			q = number.getPrime(length)
			r = number.getPrime(length)
			if number.isPrime(2*p*q+1) and number.isPrime(2*r+1):
				'''
				j += 1
				n = 4*p*q*r + 2*p*q + 2*r + 1
				for g in range(generator_range-2):
					if self.isGenerator(g+2, p, q, r, n):
						break
				if g != generator_range-3:
					break
				'''
				break
		n = 4*p*q*r + 2*p*q + 2*r + 1
		u = pow(2, 4*q*r, n)
		self.moduli = n
		self.verification_exponent = p
		self.generator = 2
		self.local_encryption_base = u

	def get_all(self):
		return self.moduli, self.verification_exponent, self.generator, self.local_encryption_base
