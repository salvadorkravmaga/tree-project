from src.cryptography import address, messages, encrypt, decrypt
from src.proof import proof_of_work
import time
import sqlite3 as sql
import requests
from hashlib import sha256
import ConfigParser

def create_payload(account):
	try:
		config = ConfigParser.RawConfigParser()
		config.read("treec")
		try:
			dApps_setting = config.get(account, 'dApps')
			dApps_setting_details = dApps_setting.split(",")
			if "OSP" in dApps_setting_details:
				dApps_setting_details.remove("OSP")
			if len(dApps_setting_details) > 0:
				additional2 = ','.join(dApps_setting_details)
				additional2 = additional2.encode("hex")
			else:
				additional2 = "None".encode("hex")
		except:
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
