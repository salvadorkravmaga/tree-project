import socket
from src.cryptography import address, messages, encrypt, decrypt
import time
import sqlite3 as sql
import requests
import ipaddress
import os

def whatis(ip):
	try:
		result = ipaddress.ip_address(unicode(ip))
		return str(result.version)
	except:
		return False

def get_encryption(Identifier,peer,user,privkey,pubkey,ip):
	try:
		if ip == "4":
			return_data = requests.get("http://"+peer+":12995/encrypt")
		else:
			return_data = requests.get("http://["+peer+"]:12995/encrypt")
		userPublicKey = return_data.content
		ourEncryptionKey = (os.urandom(32)).encode("hex")
		payload = encrypt.encryptwithPubKey(userPublicKey,ourEncryptionKey)
		if payload == False:
			return
		timestamp = str(int(time.time()))
		message = user + ":" + timestamp
		signature = messages.sign_message(privkey,message)
		signature = signature.encode("hex")
		if ip == "4":
			encryption_post = requests.post("http://"+peer+":12995/encrypt/post/"+user+"/"+pubkey+"/"+timestamp+"/"+signature, data=payload)
		else:
			encryption_post = requests.post("http://["+peer+"]:12995/encrypt/post/"+user+"/"+pubkey+"/"+timestamp+"/"+signature, data=payload)
		response = encryption_post.content
		if response != "OK":
			return
		try:
			con = sql.connect("info.db", check_same_thread=False)
			con.row_factory = sql.Row
			cur = con.cursor()
			cur.execute('SELECT * FROM fakeAccounts WHERE identifier=?', (Identifier,))
			result = cur.fetchall()
			if len(result) == 0:
				cur.execute('INSERT INTO fakeAccounts (identifier,EncryptionKey,time_generated) VALUES (?,?,?)', (Identifier,ourEncryptionKey,timestamp))
				con.commit()
			else:
				cur.execute('UPDATE fakeAccounts SET EncryptionKey=? AND time_generated=? WHERE identifier=?', (ourEncryptionKey,timestamp, Identifier))
				con.commit()
		except:
			return
		finally:
			try:
				con.close()
			except:
				pass
	except:
		pass

def get(peer):
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
	except:
		pass
	try:
		ip_result = whatis(peer)
		if ip_result == False:
			cur.execute('DELETE FROM peers WHERE peer=?', (peer,))
			con.commit()
			return
		if ip_result == "4":
			return_data = requests.get("http://"+peer+":12995/info")
		else:
			return_data = requests.get("http://["+peer+"]:12995/info")
		return_data = return_data.content
		return_data_details = return_data.split(",")
		Identifier = return_data_details[0]
		Public_key = return_data_details[1]
		Signature = return_data_details[2]
		Timestamp = return_data_details[3]
		Message = Identifier + ":" + Timestamp
		prove_ownership = messages.verify_message(Public_key,Signature,Message)
		if prove_ownership == False:
			return
		cur.execute('SELECT * FROM peers WHERE identifier=? OR peer=?', (Identifier,peer))
		result = cur.fetchall()
		if len(result) == 0:
			cur.execute('INSERT INTO peers (peer,identifier) VALUES (?,?)', (peer,Identifier))
			con.commit()
		else:
			cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
			result = cur.fetchall()
			if len(result) == 1:
				cur.execute('UPDATE peers SET identifier=? WHERE peer=?', (Identifier,peer))
				con.commit()
			else:
				cur.execute('UPDATE peers SET peer=? WHERE identifier=?', (peer,Identifier))
				con.commit()
		try:
			cur.execute('SELECT * FROM fake_account')
			result = cur.fetchall()
			fakeIdentifier = result[0]["fakeidentifier"]
			fakePrivateKey = result[0]["fake_private_key_hex"]
			fakePublicKey = result[0]["fake_public_key_hex"]
			cur.execute('SELECT * FROM fakeAccounts WHERE identifier=?', (Identifier,))
			result = cur.fetchall()
			if len(result) == 0:
				get_encryption(Identifier,peer,fakeIdentifier,fakePrivateKey,fakePublicKey,ip_result)
			elif len(result) == 1:
				time_generated = result[0]["time_generated"]
				if time.time() - float(time_generated) > 1750:
					get_encryption(Identifier,peer,fakeIdentifier,fakePrivateKey,fakePublicKey,ip_result)
			else:
				return
		except:
			pass
	except:
		cur.execute('DELETE FROM peers WHERE peer=?', (peer,))
		con.commit()
	finally:
		try:
			con.close()
		except:
			pass
