from src.cryptography import address, messages, encrypt, decrypt
from src.proof import proof_of_work
import time
import sqlite3 as sql
import requests
from hashlib import sha256

def create_payload(account):
	try:
		additional2 = "None".encode("hex")
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM accounts WHERE identifier=?', (account,))
		accounts = cur.fetchall()
		private_key_hex = accounts[0]["private_key_hex"]
		public_key_hex = accounts[0]["public_key_hex"]
		cur.execute('SELECT * FROM keys WHERE identifier=? ORDER BY time_generated DESC LIMIT 1', (account,))
		keys = cur.fetchall()
		public_key = keys[-1]["public_key"]
		data = public_key
		data = data.encode("hex")
		timestamp = str(int(time.time()))
		final = "OSP" + ":" + account + ":" + account + ":" + timestamp + ":" + "None" + ":" + additional2 + ":" + public_key_hex + ":" +data
		tx_hash = sha256(final.rstrip()).hexdigest()
		signature = messages.sign_message(private_key_hex, tx_hash)
		payload = "OSP" + "," + account + "," + account + "," + timestamp + "," + "None" + "," + additional2 + "," + public_key_hex + "," + data + "," + tx_hash + "," + signature.encode("hex")
		return payload
	except:
		return False
	finally:
		try:
			con.close()
		except:
			pass

def online_status(account):
	try:
		payload = create_payload(account)
		if payload == False:
			return
		return_data = requests.post("http://127.0.0.1:12995/data/pool/new", data=payload)
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass
