import os
import ecdsa
import hashlib
import base58

def verify_message(public_key, signature, message):
	try:
		vk = ecdsa.VerifyingKey.from_string(public_key.decode("hex"), curve=ecdsa.SECP256k1)
		result = vk.verify(signature.decode("hex"), message)
		if result:
			return True
		else:
			return False
	except:
		return False

def sign_message(private_key, message):
	try:
		sk = ecdsa.SigningKey.from_string(private_key.decode("hex"), curve = ecdsa.SECP256k1)
		sig = sk.sign(message)
		return sig
	except:
		return False
