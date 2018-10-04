from Crypto.PublicKey import RSA

def generate():
	try:
		private_key = RSA.generate(2048)
		public_key = private_key.publickey()
		private_key = private_key.exportKey()
		public_key = public_key.exportKey()
		return private_key,public_key
	except:
		print "Install all required libraries first."

def generate_encryption_key():
	try:
		private_key = RSA.generate(4096)
		public_key = private_key.publickey()
		private_key = private_key.exportKey()
		public_key = public_key.exportKey()
		return private_key,public_key
	except:
		print "Install all required libraries first."
