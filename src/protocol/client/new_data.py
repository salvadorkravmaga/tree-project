import socket
from src.cryptography import address, messages, encrypt, decrypt
import time
import sqlite3 as sql
import requests

def new_data(account,peer,payload):
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
			return
		timestamp = str(int(time.time()))
		signature = messages.sign_message(private_key_hex, Address+":"+timestamp)
		signature = signature.encode("hex")
		return_data = requests.post("http://"+peer+":12995/data/new/"+Address+"/"+public_key_hex+"/"+timestamp+"/"+signature, data=payload)
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass
