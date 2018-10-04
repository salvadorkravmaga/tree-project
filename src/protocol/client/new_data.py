from src.cryptography import address, messages, encrypt
from src.proof import proof_of_work
import time
import sqlite3 as sql
import requests
import ipaddress

def whatis(ip):
	try:
		result = ipaddress.ip_address(unicode(ip))
		return str(result.version)
	except:
		return False

def new_data(peer,payload):
	try:
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
				usersEncryptionKey = result[0]["usersEncryptionKey"]
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
