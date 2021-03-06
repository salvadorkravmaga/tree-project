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
	payload = "OSP" + "," + sender + "," + receiver + "," + timestamp + "," + additional1 + "," + additional2 + "," + additional3 + "," + data + "," + tx_hash + "," + signature
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
				Protocols = []
				for protocol in protocols_details:
					if protocol not in Protocols:
						Protocols.append(protocol)
				if "OSP" in Protocols:
					Protocols.remove("OSP")
				if len(Protocols) > 0:
					protocols = ','.join(Protocols)
				else:
					protocols = "None"
			except:
				return False
			if Data != "None" and Data != "":
				cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
				result = cur.fetchall()
				if len(result) == 0:
					cur.execute('INSERT INTO users (identifier,public_key_hex,public_key,last_online,protocols,payload) VALUES (?,?,?,?,?,?)', (sender,additional3,Data,timestamp,protocols,payload))
					con.commit()
				else:
					Protocols = result[0]["protocols"]
					PROTOCOLS = []
					if protocols != "None":
						protocols_details = protocols.split(",")
						for protocol in protocols_details:
							if protocol not in PROTOCOLS:
								PROTOCOLS.append(protocol)
					if Protocols != "None":
						protocols_details = Protocols.split(",")
						for protocol in protocols_details:
							if protocol not in PROTOCOLS:
								PROTOCOLS.append(protocol)
					if len(PROTOCOLS) == 0:
						PROTOCOLS = "None"
					else:
						PROTOCOLS = ','.join(PROTOCOLS)
					cur.execute('UPDATE users SET public_key=?,last_online=?,protocols=?,payload=? WHERE identifier=?', (Data,timestamp,PROTOCOLS,payload,sender))
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
