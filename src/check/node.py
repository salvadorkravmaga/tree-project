from src.cryptography import decrypt, address, messages
from src.check import operations
from hashlib import sha256
import time
import sqlite3 as sql
import requests
import os.path
import ConfigParser
import sys
import StringIO
import contextlib

try:
	config = ConfigParser.RawConfigParser()
	config.read("treec")
	dapps = config.get('Configuration', 'dApps')
	dapps_details = dapps.split(",")
except:
	pass

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
				cur.execute('DELETE FROM users WHERE identifier=?', (sender,))
				con.commit()
				cur.execute('INSERT INTO users (identifier,public_key_hex,public_key,last_online,protocols) VALUES (?,?,?,?,?)', (sender,additional3,Data,timestamp,protocols))
				con.commit()
				payload = tx_hash + "," + timestamp
				my_transactions_post = requests.post("http://127.0.0.1:12995/tx/new", data=payload)
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
	if operation in dapps_details:
		sender = details[1]
		test_ban = check_ban(sender)
		if test_ban == "True":
			return result
		receiver = details[2]
		receiver = receiver[0:]
		timestamp = details[3]
		data = details[7]
		signature = details[9]
		if operation == "OSP":
			result = online_status(sender,receiver,timestamp,additional1,additional2,additional3,data,tx_hash,signature)
		else:
			posted = False
			posted_tries = 0
			while posted == False and posted_tries < 3:
				try:
					dApps_post = requests.post("http://127.0.0.1:12995/dApps/new", data=payload)
					posted = True
				except:
					posted_tries += 1
					time.sleep(1)
			payload = tx_hash + "," + timestamp
			my_transactions_post = requests.post("http://127.0.0.1:12995/tx/new", data=payload)
			result = "True"
		return result
	else:
		return result
