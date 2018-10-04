# -*- coding: utf-8 -*-

from base64 import *
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import sqlite3 as sql

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

base64pad = lambda s: s + '=' * (4 - len(s) % 4)
base64unpad = lambda s: s.rstrip("=")

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
					rsakey = RSA.importKey(privateKey)
					encrypted = message
					raw_cipher_data = b64decode(encrypted)
					decrypted = rsakey.decrypt(raw_cipher_data)
					return decrypted
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

def decryptWithRSAKey(key, msg):
	try:
		key = key.decode("hex")
	    	decoded_msg = urlsafe_b64decode(base64pad(msg))
	    	iv = decoded_msg[:BS]
	    	encrypted_msg = decoded_msg[BS:] 
	    	cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=AES.block_size * 8)
	    	return unpad(cipher.decrypt(encrypted_msg))
	except:
		return False
