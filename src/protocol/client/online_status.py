from src.cryptography import address, messages, encrypt, decrypt
from src.proof import proof_of_work
import time
import sqlite3 as sql
import requests
from hashlib import sha256
import ConfigParser
import ipaddress

def whatis(ip):
	try:
		result = ipaddress.ip_address(unicode(ip))
		return str(result.version)
	except:
		return False

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

def online_status(account,peer):
	try:
		payload = create_payload(account)
		if payload == False:
			return
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM fake_account')
		accounts = cur.fetchall()
		Account = accounts[0]["fakeidentifier"]
		private_key_hex = accounts[0]["fake_private_key_hex"]
		public_key_hex = accounts[0]["fake_public_key_hex"]
		Address = address.keyToAddr2(public_key_hex, Account)
		timestamp = str(int(time.time()))
		signature = messages.sign_message(private_key_hex, Address+":"+timestamp)
		signature = signature.encode("hex")
		ip_result = whatis(peer)
		if ip_result == False:
			return
		if ip_result == "4":
			return_data = requests.get("http://"+peer+":12995/proofofwork/"+Address+"/"+public_key_hex+"/"+timestamp+"/"+signature)
		else:
			return_data = requests.get("http://["+peer+"]:12995/proofofwork/"+Address+"/"+public_key_hex+"/"+timestamp+"/"+signature)
		mining = return_data.content
		mining_details = mining.split(",")
		hashed = mining_details[0]
		deadline = mining_details[1]
		nonce = "None"
		if hashed != "None" and deadline != "None":
			nonce = proof_of_work.solve(hashed,deadline)
			if nonce == False:
				return
		cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
		result = cur.fetchall()
		if len(result) == 1:
			fakeIdentifier = result[0]["identifier"]
			cur.execute('SELECT * FROM fakeAccounts WHERE identifier=?', (fakeIdentifier,))
			result = cur.fetchall()
			if len(result) == 1:
				usersEncryptionKey = result[0]["EncryptionKey"]
			else:
				return
		else:
			return
		payload = encrypt.encryptWithRSAKey(usersEncryptionKey,payload)
		if payload == False:
			return
		if ip_result == "4":
			return_data = requests.post("http://"+peer+":12995/data/new/"+Address+"/"+public_key_hex+"/"+timestamp+"/"+signature+"/"+hashed+"/"+nonce, data=payload)
		else:
			return_data = requests.post("http://["+peer+"]:12995/data/new/"+Address+"/"+public_key_hex+"/"+timestamp+"/"+signature+"/"+hashed+"/"+nonce, data=payload)
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass
