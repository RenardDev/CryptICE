
__name__ = 'CryptICE'
__author__ = '𝓡𝓮𝓷'
__url__ = 'https://steamcommunity.com/id/RenXR/'
__version__ = '1.0.2'

__all__ = [
	'IceKey'
]

class IceKey(object):
	# Modulo values for the S-boxes
	__rSMOD = [
		[ 333, 313, 505, 369 ],
		[ 379, 375, 319, 391 ],
		[ 361, 445, 451, 397 ],
		[ 397, 425, 395, 505 ],
	]
	# XOR values for the S-boxes
	__rSXOR = [
		[ 0x83, 0x85, 0x9B, 0xCD ],
		[ 0xCC, 0xA7, 0xAD, 0x41 ],
		[ 0x4B, 0x2E, 0xD4, 0x33 ],
		[ 0xEA, 0xCB, 0x2E, 0x04 ],
	]
	# Expanded permutation values for the P-box
	__rPBOX = [
		0x00000001, 0x00000080, 0x00000400, 0x00002000,
		0x00080000, 0x00200000, 0x01000000, 0x40000000,
		0x00000008, 0x00000020, 0x00000100, 0x00004000,
		0x00010000, 0x00800000, 0x04000000, 0x20000000,
		0x00000004, 0x00000010, 0x00000200, 0x00008000,
		0x00020000, 0x00400000, 0x08000000, 0x10000000,
		0x00000002, 0x00000040, 0x00000800, 0x00001000,
		0x00040000, 0x00100000, 0x02000000, 0x80000000,
	]
	# The key rotation schedule
	__rKEYROT = [
		0, 1, 2, 3, 2, 1, 3, 0,
		1, 3, 2, 0, 3, 1, 0, 2,
	]
	__rKEY_SCHEDULE = dict()
	__rSBOX = dict()
	__rSBOX_INITIALISED = False
	__rSIZE = 0
	__rROUNDS = 0
	# Helpful functions
	def __GenerateArray(self, size:int, value:int=0) -> list:
		array = list()
		for _ in range(size):
			array.append(value)
		return array
	# Main functions
	'''
	Galois Field multiplication of a by b, modulo m.
	Just like arithmetic multiplication, except that additions and subtractions are replaced by XOR.
	'''
	def gf_mult(self, a:int, b:int, m:int) -> int:
		res = 0
		while b:
			if b & 1:
				res ^= a
			a <<= 1
			b >>= 1
			if a >= 256:
				a ^= m
		return res
	'''
	Galois Field exponentiation.
	Raise the base to the power of 7, modulo m.
	'''
	def gf_exp7(self, b:int, m:int) -> int:
		if b == 0:
			return 0
		x = self.gf_mult(b, b, m)
		x = self.gf_mult(b, x, m)
		x = self.gf_mult(x, x, m)
		return self.gf_mult(b, x, m)
	'''
	Carry out the ICE 32-bit P-box permutation.
	'''
	def perm32(self, x:int) -> int:
		res = 0
		i = 0
		while x:
			if (x & 1):
				res |= self.__rPBOX[i % len(self.__rPBOX)]
			i += 1
			x >>= 1
		return res
	'''
	Create a new ICE object.
	'''
	def __init__(self, n:int, key:bytes):
		if self.__rSBOX_INITIALISED != True:
			self.__rSBOX.clear()
			for i in range(0, 4):
				self.__rSBOX[i] = dict()
				for l in range(0, 1024):
					self.__rSBOX[i][l] = 0x00
			for i in range(0, 1024):
				col = (i >> 1) & 0xFF
				row = (i & 0x1) | ((i & 0x200) >> 8)
				self.__rSBOX[0][i] = self.perm32(self.gf_exp7(col ^ self.__rSXOR[0][row], self.__rSMOD[0][row]) << 24)
				self.__rSBOX[1][i] = self.perm32(self.gf_exp7(col ^ self.__rSXOR[1][row], self.__rSMOD[1][row]) << 16)
				self.__rSBOX[2][i] = self.perm32(self.gf_exp7(col ^ self.__rSXOR[2][row], self.__rSMOD[2][row]) << 8)
				self.__rSBOX[3][i] = self.perm32(self.gf_exp7(col ^ self.__rSXOR[3][row], self.__rSMOD[3][row]))
			self.__rSBOX_INITIALISED = True
		if n < 1:
			self.__rSIZE = 1
			self.__rROUNDS = 8
		else:
			self.__rSIZE = n
			self.__rROUNDS = n * 16
		for i in range(0, self.__rROUNDS):
			self.__rKEY_SCHEDULE[i] = dict()
			for j in range(0, 4):
				self.__rKEY_SCHEDULE[i][j] = 0x00
		if self.__rROUNDS == 8:
			kb = self.__GenerateArray(4)
			for i in range(0, 4):
				kb[3 - i] = (key[i * 2] << 8) | key[i * 2 + 1]
			for i in range(0, 8):
				kr = self.__rKEYROT[i]
				isk = self.__rKEY_SCHEDULE[i]
				for j in range(0, 15):
					for k in range(0, 4): 
						bit = kb[(kr + k) & 3] & 1
						isk[j % 3] = (isk[j % 3] << 1) | bit
						kb[(kr + k) & 3] = (kb[(kr + k) & 3] >> 1) | ((bit ^ 1) << 15)
		for i in range(0, self.__rSIZE):
			kb = self.__GenerateArray(4)
			for j in range(0, 4):
				kb[3 - j] = (key[i * 8 + j * 2] << 8) | key[i * 8 + j * 2 + 1]
			for l in range(0, 8):
				kr = self.__rKEYROT[l]
				isk = self.__rKEY_SCHEDULE[((i * 8) + l) % len(self.__rKEY_SCHEDULE)]
				for j in range(0, 15):
					for k in range(0, 4):
						bit = kb[(kr + k) & 3] & 1
						isk[j % 3] = (isk[j % 3] << 1) | bit
						kb[(kr + k) & 3] = (kb[(kr + k) & 3] >> 1) | ((bit ^ 1) << 15)
			for l in range(0, 8):
				kr = self.__rKEYROT[8 + l]
				isk = self.__rKEY_SCHEDULE[((self.__rROUNDS - 8 - i * 8) + l) % len(self.__rKEY_SCHEDULE)]
				for j in range(0, 15): 
					for k in range(0, 4):
						bit = kb[(kr + k) & 3] & 1
						isk[j % 3] = (isk[j % 3] << 1) | bit
						kb[(kr + k) & 3] = (kb[(kr + k) & 3] >> 1) | ((bit ^ 1) << 15)
	'''
	The single round ICE f function.
	'''
	def _ice_f(self, p:int, sk:int) -> int:
		tl = ((p >> 16) & 0x3FF) | (((p >> 14) | (p << 18)) & 0xFFC00)
		tr = (p & 0x3FF) | ((p << 2) & 0xFFC00)
		al = sk[2] & (tl ^ tr)
		ar = al ^ tr
		al ^= tl
		al ^= sk[0]
		ar ^= sk[1]
		return self.__rSBOX[0][al >> 10] | self.__rSBOX[1][al & 0x3FF] | self.__rSBOX[2][ar >> 10] | self.__rSBOX[3][ar & 0x3FF]
	'''
	Return the key size, in bytes.
	'''
	def KeySize(self) -> int:
		return self.__rSIZE * 8
	'''
	Return the block size, in bytes.
	'''
	def BlockSize(self) -> int:
		return 8
	'''
	Encrypt a block of 8 bytes of data with the given ICE key.
	'''
	def EncryptBlock(self, data:list) -> list:
		out = self.__GenerateArray(8)
		l = 0
		r = 0
		for i in range(0, 4):
			l |= (data[i] & 0xFF) << (24 - i * 8)
			r |= (data[i + 4] & 0xFF) << (24 - i * 8)
		for i in range(0, self.__rROUNDS, 2):
			l ^= self._ice_f(r, self.__rKEY_SCHEDULE[i])
			r ^= self._ice_f(l, self.__rKEY_SCHEDULE[i + 1])
		for i in range(0, 4):
			out[3 - i] = r & 0xFF
			out[7 - i] = l & 0xFF
			r >>= 8
			l >>= 8
		return out
	'''
	Decrypt a block of 8 bytes of data with the given ICE key.
	'''
	def DecryptBlock(self, data:list) -> list:
		out = self.__GenerateArray(8)
		l = 0
		r = 0
		for i in range(0, 4):
			l |= (data[i] & 0xFF) << (24 - i * 8)
			r |= (data[i + 4] & 0xFF) << (24 - i * 8)
		for i in range(self.__rROUNDS - 1, 0, -2):
			l ^= self._ice_f(r, self.__rKEY_SCHEDULE[i])
			r ^= self._ice_f(l, self.__rKEY_SCHEDULE[i - 1])
		for i in range(0, 4):
			out[3 - i] = r & 0xFF
			out[7 - i] = l & 0xFF
			r >>= 8
			l >>= 8
		return out
	'''
	Encrypt the data byte array with the given ICE key.
	'''
	def Encrypt(self, data:bytes, cmspadding:bool=False) -> bytes:
		if cmspadding:
			blocksize = self.BlockSize()
			padding_length = blocksize - (len(data) % blocksize)
			data += bytes(self.__GenerateArray(padding_length, padding_length))
		out = bytearray()
		blocksize = self.BlockSize()
		bytesleft = len(data)
		i = 0
		while bytesleft >= blocksize:
			out.extend(self.EncryptBlock(data[i:i + blocksize]))
			bytesleft -= blocksize
			i += blocksize
		if bytesleft > 0:
			out.extend(data[len(data)-bytesleft:len(data)])
		return bytes(out)
	'''
	Decrypt the data byte array with the given ICE key.
	'''
	def Decrypt(self, data:bytes, cmspadding:bool=False) -> bytes:
		out = bytearray()
		blocksize = self.BlockSize()
		bytesleft = len(data)
		i = 0
		while bytesleft >= blocksize:
			out.extend(self.DecryptBlock(data[i:i + blocksize]))
			bytesleft -= blocksize
			i += blocksize
		if bytesleft > 0:
			out.extend(data[len(data)-bytesleft:len(data)])
		if cmspadding:
			out_length = len(out)
			for i in range(1, out[-1] + 1):
				del out[out_length - i]
		return bytes(out)
