# -*- coding: utf-8 -*-

import base64
from Crypto.Cipher import AES, PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.PublicKey import RSA

BLOCK_SIZE = 32
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

def encryptwithPubKey(publicKey,text):
	try:
		keyPub = RSA.importKey(publicKey)
		cipher = Cipher_PKCS1_v1_5.new(keyPub)
		cipher_text = cipher.encrypt(text.encode())
		emsg = base64.b64encode(cipher_text)
		return emsg
	except Exception as e:
		print e
		return False

def encryptAES(key, msg):
	try:
		cipher = AES.new(key.decode("hex"))
		encrypted = EncodeAES(cipher,msg)
		return encrypted
	except:
		return False
