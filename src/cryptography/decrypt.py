from Crypto.PublicKey import RSA
from base64 import *
import sqlite3 as sql
import requests
import os

def decrypt(account):
	try:
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM keys WHERE identifier=?', (account,))
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
