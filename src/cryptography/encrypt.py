# -*- coding: utf-8 -*-

from base64 import *
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import time

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

base64pad = lambda s: s + '=' * (4 - len(s) % 4)
base64unpad = lambda s: s.rstrip("=")

def encryptwithPubKey(publicKey,text):
	try:
		publicKey = RSA.importKey(publicKey,None)
		enc=publicKey.encrypt(text,None)[0]
		encb64 = encodestring(enc)
		encb64 = encb64.replace("\n","")
		return encb64
	except Exception as e:
		print e
		return False

def encryptWithRSAKey(key, msg):
	try:
		key = key.decode("hex")
		iv = Random.new().read(BS)
	    	cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=AES.block_size * 8)
	    	encrypted_msg = cipher.encrypt(pad(str(msg)))
	    	return base64unpad(urlsafe_b64encode(iv + encrypted_msg))
	except:
		return False
