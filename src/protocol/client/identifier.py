import socket
from src.cryptography import address, messages, encrypt, decrypt
import time
import sqlite3 as sql
import requests

def get(account,peer):
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
	except:
		pass
	try:
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
		cur.execute('SELECT * FROM peers WHERE identifier=?', (Identifier,))
		result = cur.fetchall()
		if len(result) == 0:
			cur.execute('INSERT INTO peers (peer,identifier) VALUES (?,?)', (peer,Identifier))
			con.commit()
		else:
			cur.execute('UPDATE peers SET peer=? WHERE identifier=?', (peer,Identifier))
			con.commit()
	except:
		cur.execute('DELETE FROM peers WHERE peer=?', (peer,))
		con.commit()
	finally:
		try:
			con.close()
		except:
			pass
