from src.cryptography import decrypt, address, messages
from src.check import operations
from hashlib import sha256
import time
import sqlite3 as sql
import requests

def check_ban(identifier):
	try:
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
	except:
		pass
	try:
		cur.execute('SELECT * FROM banlist WHERE identifier=?', (identifier,))
		banlist = cur.fetchall()
		if len(banlist) > 0:
			time_banned = banlist["time"]
			time_now = time.time()
			if time_now - float(time_banned) > 86400:
				return False
			else:
				return True
		else:
			return False
	except:
		return False
	finally:
		try:
			con.close()
		except:
			pass

def ban(identifier):
	try:
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
	except:
		pass
	try:
		cur.execute('SELECT * FROM banlist WHERE identifier=?', (identifier,))
		banlist = cur.fetchall()
		if len(banlist) < 1:
			time_now = str(time.time())
			cur.execute('INSERT INTO banlist (identifier,time) VALUES (?,?)', (identifier,time_now))
			con.commit()
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass

def online_status(sender,receiver,timestamp,additional1,additional2,additional3,data,tx_hash,signature):
	try:
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
	except:
		pass
	try:
		if sender != receiver:
			return False
		if additional1 == "None":
			try:
				Data = data.decode("hex")
			except:
				return False
			try:
				protocols = additional2.decode("hex")
				protocols_details = protocols.split(",")
				if "OSP" in protocols_details:
					protocols_details.remove("OSP")
				if len(protocols_details) > 0:
					protocols = ','.join(protocols_details)
				else:
					protocols = "None"
			except:
				return False
			if Data != "None" and Data != "":
				cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
				result = cur.fetchall()
				if len(result) == 0:
					cur.execute('INSERT INTO users (identifier,public_key_hex,public_key,last_online,protocols) VALUES (?,?,?,?,?)', (sender,additional3,Data,timestamp,protocols))
					con.commit()
				else:
					cur.execute('UPDATE users SET public_key=?,last_online=?,protocols=? WHERE identifier=?', (Data,timestamp,protocols,sender))
					con.commit()
				return True
			else:
				return False
		else:
			return False
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass

def constructor(payload):
	result = False
	details = payload.split(",")
	operation = details[0]
	receiver = details[2]
	additional1 = details[4]
	additional2 = details[5]
        additional3 = details[6]
	tx_hash = details[8]
	get_tx_status = False
	get_tx_status_tries = 0
	while get_tx_status == False and get_tx_status_tries < 3:
		try:
			check_my_transactions = requests.get("http://127.0.0.1:12995/tx/"+tx_hash)
			get_tx_status = True
			if check_my_transactions.content == "True":
				return result
		except:
			get_tx_status_tries += 1
			time.sleep(2)
	if operation == "OSP":
		sender = details[1]
		test_ban = check_ban(sender)
		if test_ban == "True":
			return result
		timestamp = details[3]
		data = details[7]
		signature = details[9]
		result = online_status(sender,receiver,timestamp,additional1,additional2,additional3,data,tx_hash,signature)
		return result
	else:
		return result
