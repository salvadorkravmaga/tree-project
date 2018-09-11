from src.cryptography import address, messages, encrypt, decrypt
import time
import sqlite3 as sql
import requests
from hashlib import sha256

def get(account,peer,user):
	try:
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM accounts WHERE identifier=?', (account,))
		accounts = cur.fetchall()
		private_key_hex = accounts[0]["private_key_hex"]
		public_key_hex = accounts[0]["public_key_hex"]
		Address = address.keyToAddr(public_key_hex)
		return_data = requests.get("http://"+peer+":12995/account/main/"+Address)
		return_data = return_data.content
		return_data_details = return_data.split(",")
		Identifier = return_data_details[0]
		Public_key = return_data_details[1]
		Signature = return_data_details[2]
		prove_ownership = messages.verify_message(Public_key,Signature,Address)
		if prove_ownership == False:
			return False,False
		return_data = requests.get("http://"+peer+":12995/user/"+user)
		if return_data.content != "None" and return_data.status == 200:
			return Identifier,return_data.content
		else:
			return False,False
	except:
		return False,False
	finally:
		try:
			con.close()
		except:
			pass
