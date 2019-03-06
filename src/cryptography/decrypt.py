# -*- coding: utf-8 -*-

import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import sqlite3 as sql

BLOCK_SIZE = 32
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

def decryptfromPubKey(message):
	try:
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM encryption_key')
		keys = cur.fetchall()
		if len(keys) >= 1:
			for key in keys:
				try:
					privateKey = key["private_key"]
					keyPub = RSA.importKey(privateKey)
					cipher = Cipher_PKCS1_v1_5.new(keyPub)
					cipher_text = base64.b64decode(message)
					decrypt_text = cipher.decrypt(cipher_text, None).decode()
					return decrypt_text
				except:
					pass
			return False
		else:
			return False
	except:
		return False
	finally:
		try:
			con.close()
		except:
			pass

def decryptAES(key, msg):
	try:
		cipher = AES.new(key.decode("hex"))
		decrypted = DecodeAES(cipher,msg)
		return decrypted
	except:
		return False
