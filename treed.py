#!/usr/bin/env python
# -*- coding: utf-8 -*-

from src.cryptography import address, messages, keys, encrypt, decrypt
from src.protocol.client import identifier, new_data, online_status, other_nodes
from src.protocol import other_nodes_get
from src.check import operations, node
from src.database import db, structure
from src import setup
from src.proof import generator, proof_of_work
from flask import Flask, request, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from functools import wraps
import requests
import ConfigParser
import sys
import os, os.path
import inspect
import time
import sqlite3 as sql
import thread
import logging
import ipaddress
import psutil

log = logging.getLogger('werkzeug')
log.setLevel(logging.CRITICAL)

accounts = []
nodes = ["::ffff:104.200.67.51"]
connections = []
GetFromSettings = {}
PostToSettings = {}
PostTo = []
Banlist = []

path = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
config = ConfigParser.RawConfigParser()
config.read("treec")

app = Flask(__name__)


def whatis(ip):
	try:
		result = ipaddress.ip_address(unicode(ip))
		return str(result.version)
	except:
		return False

def limit_content_length(max_length):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            cl = request.content_length
            if cl is not None and cl > max_length:
                abort(413)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def test_peers():
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
			peer = request.remote_addr
			try:
				con = sql.connect("info.db", check_same_thread=False)
				con.row_factory = sql.Row
				cur = con.cursor()
				cur.execute('SELECT * FROM test_peers WHERE peer=?', (peer,))
				result = cur.fetchall()
				if len(result) == 0:
					cur.execute('INSERT INTO test_peers (peer) VALUES (?)', (peer,))
					con.commit()
			except Exception as e:
				print e
				pass
			finally:
				try:
					con.close()
				except:
					pass
			return f(*args, **kwargs)
        return wrapper
    return decorator

try:
	print "[!] Checking accounts"
	con = sql.connect("info.db", check_same_thread=False)
	con.row_factory = sql.Row
	cur = con.cursor()
	cur.execute('SELECT * FROM accounts')
	Accounts = cur.fetchall()
	cur.execute('SELECT * FROM fake_account')
	FakeAccounts = cur.fetchall()
	cur.execute('SELECT * FROM banlist')
	banlist = cur.fetchall()
	for banned_user in banlist:
		banned_identifier = banned_user["identifier"]
		banned_peer = banned_user["peer"]
		if banned_identifier not in Banlist:
			Banlist.append(banned_identifier)
		if banned_peer not in Banlist and banned_peer != "None":
			Banlist.append(banned_peer)
except:
	result = setup.config(path)
	if result == False:
		print "Something went wrong with installation. Exiting.."
		sys.exit(1)
	con = sql.connect("info.db", check_same_thread=False)
	con.row_factory = sql.Row
	cur = con.cursor()
	cur.execute('SELECT * FROM accounts')
	Accounts = cur.fetchall()
	cur.execute('SELECT * FROM fake_account')
	FakeAccounts = cur.fetchall()
	cur.execute('SELECT * FROM banlist')
	banlist = cur.fetchall()
	for banned_user in banlist:
		banned_identifier = banned_user["identifier"]
		banned_peer = banned_user["peer"]
		if banned_identifier not in Banlist:
			Banlist.append(banned_identifier)
		if banned_peer not in Banlist and banned_peer != "None":
			Banlist.append(banned_peer)

if len(Accounts) == 0:
	print "	[!] Generating new account"
	private_key_hex,public_key_hex,Accountaddress = address.generate_account()
	try:
		cur.execute('INSERT INTO accounts (identifier,private_key_hex,public_key_hex) VALUES (?,?,?)', (Accountaddress,private_key_hex,public_key_hex))
		con.commit()
	except:
		print "		[-] DB error. Exiting.."
		sys.exit(1)

	try:
		priv_key,pub_key = keys.generate()
	except:
		print "		[-] Error generating private/public keys pair. Exiting.."
		sys.exit(1)

	try:
		cur.execute('INSERT INTO keys (identifier,public_key,private_key,time_generated) VALUES (?,?,?,?)', (Accountaddress,pub_key,priv_key,str(time.time())))
		con.commit()
	except:
		print "		[-] DB error. Exiting.."
		sys.exit(1)

	print "		[+] New account " + Accountaddress + " created"
	GetFromSettings.update({Accountaddress:"ALL"})
	PostToSettings.update({Accountaddress:"ALL"})
	accounts.append(Accountaddress)
else:
	for Account in Accounts:
		try:
			account = Account["identifier"]
			private_key_hex = Account["private_key_hex"]
			public_key_hex = Account["public_key_hex"]
			Accountaddress = address.keyToAddr(public_key_hex,account)
			if Accountaddress != account:
				cur.execute('UPDATE accounts SET identifier=? WHERE identifier=?', (Accountaddress,account))
				con.commit()
			signature = messages.sign_message(private_key_hex,"test")
			if signature == False:
				print "	[-] There was a problem with signature. Exiting.."
				sys.exit(1)
			prove_ownership = messages.verify_message(public_key_hex, signature.encode("hex"), "test")
			if prove_ownership == False:
				print "	[-] The private key " + private_key_hex + " does not prove ownership of " + account
				cur.execute('DELETE FROM accounts WHERE identifier=?', (account,))
				con.commit()
			else:
				print "	[+] Account successfully loaded: " + account
				accounts.append(account)
		except:
			print "	[-] Error with private key. Maybe wrong format (WIF)? Exiting.."
			sys.exit(1)

if len(FakeAccounts) == 0:
	print "	[!] Generating new fake account"
	fake_private_key_hex,fake_public_key_hex,fakeAccountaddress = address.generate_fakeIdentifier()
	try:
		cur.execute('INSERT INTO fake_account (fakeidentifier,fake_private_key_hex,fake_public_key_hex) VALUES (?,?,?)', (fakeAccountaddress,fake_private_key_hex,fake_public_key_hex))
		con.commit()
	except:
		print "		[-] DB error. Exiting.."
		sys.exit(1)
	print "		[+] New fake account " + fakeAccountaddress + " created"
elif len(FakeAccounts) == 1:
	try:
		fake_account = FakeAccounts[0]["fakeidentifier"]
		fake_private_key_hex = FakeAccounts[0]["fake_private_key_hex"]
		fake_public_key_hex = FakeAccounts[0]["fake_public_key_hex"]
		fake_Accountaddress = address.keyToAddr2(fake_public_key_hex,fake_account)
		if fake_Accountaddress != fake_account:
			cur.execute('UPDATE fake_account SET identifier=? WHERE identifier=?', (fake_Accountaddress,fake_account))
			con.commit()
		signature = messages.sign_message(fake_private_key_hex,"test")
		if signature == False:
			print "	[-] There was a problem with signature. Exiting.."
			sys.exit(1)
		prove_ownership = messages.verify_message(fake_public_key_hex, signature.encode("hex"), "test")
		if prove_ownership == False:
			print "	[-] The private key " + fake_private_key_hex + " does not prove ownership of " + fake_account
			cur.execute('DELETE FROM fake_account WHERE identifier=?', (fake_account,))
			con.commit()
		else:
			print "	[+] Fake account successfully loaded: " + fake_account
	except:
		print "	[-] Error with private key. Maybe wrong format (WIF)? Exiting.."
		sys.exit(1)
else:
	print "	[-] More than one fake account detected. Exiting.."
	sys.exit(1)

for account in accounts:
	try:
		post_to_setting = config.get(account, 'PostTo')
		post_to_setting = post_to_setting.replace(" ","")
		PostToSettings.update({account:post_to_setting})
	except:
		PostToSettings.update({account:"ALL"})

	try:
		get_from_setting = config.get(account, 'GetFrom')
		get_from_setting = get_from_setting.replace(" ","")
		GetFromSettings.update({account:get_from_setting})
	except:
		GetFromSettings.update({account:"ALL"})

@app.route('/other/nodes', methods=['GET'])
def get_other_nodes():
	if request.remote_addr not in Banlist:
		other_nodes = other_nodes_get.get()
		if other_nodes == "":
			return "None"
		else:
			return other_nodes
	else:
		abort(403)

@app.route('/connections/<account>', methods=['GET'])
def connections_account(account):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		returned_connections = []
		for connection in connections:
			connection_details = connection.split(",")
			Account = connection_details[0]
			peer = connection_details[1]
			if Account == account:
				returned_connections.append(peer)
		result = ','.join(returned_connections)
		return result
	else:
		abort(403)

@app.route('/memory/pool/new', methods=['POST'])
def memory_pool_new():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		try:
			mixed = False
			con = sql.connect("info.db", check_same_thread=False)
			con.row_factory = sql.Row
			cur = con.cursor()
			payload = request.data
			payload_details = payload.split(",")
			operation = payload_details[0]
			sender = payload_details[1]
			sender_details = sender.split("|")
			if len(sender_details) > 1:
				mixed = True
			receiver = payload_details[2]
			receiver_details = receiver.split("|")
			time_added = payload_details[3]
			if time.time() - float(time_added) > 600:
				return "Done"
			if operation != "OSP":
				for Sender in sender_details:
					found = False
					cur.execute('SELECT * FROM users WHERE identifier=?', (Sender,))
					result = cur.fetchall()
					if len(result) == 1:
						last_online = result[0]["last_online"]
						if time.time() - float(last_online) < 420:
							found = True
					if found == False:
						return "Done"
				if mixed == False:
					cur.execute('SELECT * FROM cache WHERE sender=? AND receiver=?', (sender_details[0],receiver_details[0]))
					result = cur.fetchall()
					times_found = len(result)
					if times_found >= 5:
						return "Done"
			if operation != "OSP":
				for Receiver in receiver_details:
					found = False
					cur.execute('SELECT * FROM users WHERE identifier=?', (Receiver,))
					result = cur.fetchall()
					if len(result) == 1:
						last_online = result[0]["last_online"]
						if time.time() - float(last_online) < 420:
							found = True
					if found == False:
						return "Done"
					else:
						cur.execute('SELECT * FROM users WHERE identifier=?', (Receiver,))
						result = cur.fetchall()
						if len(result) == 1:
							supportedDAPPS = result[0]["protocols"]
							supportedDAPPS_details = supportedDAPPS.split(",")
							if operation not in supportedDAPPS_details or operation == "None":
								return "Done"
						else:
							return "Done"
			if mixed == False:
				if operation != "OSP":
					cur.execute('SELECT * FROM connections WHERE sender=? AND receiver=?', (sender_details[0],receiver_details[0]))
					result = cur.fetchall()
					if len(result) == 1:
						times_connected = result[0]["times_connected"]
						if int(times_connected) >= 10:
							return "Done"
						else:
							times_connected_updated = int(times_connected) + 1
							cur.execute('UPDATE connections SET times_connected=? WHERE sender=? AND receiver=?', (times_connected_updated, sender_details[0],receiver_details[0]))
							con.commit()
							cur.execute('SELECT * FROM connections WHERE sender=? AND receiver=?', (receiver,sender))
							result = cur.fetchall()
							if len(result) == 1:
								cur.execute('UPDATE connections SET times_connected=? WHERE sender=? AND receiver=?', ("0",receiver_details[0],sender_details[0]))
								con.commit()
					else:
						cur.execute('INSERT INTO connections (sender,receiver,times_connected,time) VALUES (?,?,?,?)', (sender_details[0],receiver_details[0],"0",str(time.time())))
						con.commit()
			additional1 = payload_details[4]
			data = payload_details[7]
			tx_hash = payload_details[8]
			if operation == "OSP":
				result = node.constructor(payload)
				if result == True:
					return "Data added to the pool."
				else:
					return "Done"
			else:
				if mixed == False:
					cur.execute('INSERT INTO cache (sender,receiver,time,operation,tx_hash,data,status) VALUES (?,?,?,?,?,?,?)', (sender_details[0],receiver_details[0],time_added,operation,tx_hash,payload,"KEEP"))
					con.commit()
				else:
					for Sender in sender_details:
						for Receiver in receiver_details:
							cur.execute('INSERT INTO cache (sender,receiver,time,operation,tx_hash,data,status) VALUES (?,?,?,?,?,?,?)', (Sender,Receiver,time_added,operation,tx_hash,payload,"KEEP"))
							con.commit()
				requests.post("http://127.0.0.1:12995/data/pool/new", data=payload)
				return "Data added to the pool"
		except:
			return "Something went wrong."
		finally:
			try:
				con.close()
			except:
				pass
	else:
		abort(403)

@app.route('/encrypt', methods=['GET'])
def encryption():
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM encryption_key')
		result = cur.fetchall()
		if len(result) > 0:
			public_key = result[-1]["public_key"]
			return public_key
		else:
			return "Something went wrong."
	except:
		return "Something went wrong."
	finally:
		try:
			con.close()
		except:
			pass

@app.route('/info', methods=['GET'])
@test_peers()
def nodeinfo():
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM fake_account')
		result = cur.fetchall()
		identifier = result[0]["fakeidentifier"]
		public_key = result[0]["fake_public_key_hex"]
		private_key = result[0]["fake_private_key_hex"]
		timestamp = str(int(time.time()))
		signature = messages.sign_message(private_key,identifier+":"+timestamp)
		return str(identifier + "," + public_key + "," + signature.encode("hex") + "," + timestamp)
	except Exception as e:
		print e
		return "Something went wrong."
	finally:
		try:
			con.close()
		except:
			pass

@app.route('/proofofwork/<user>/<public_key>/<timestamp>/<signature>', methods=['GET'])
def proofofwork_generate(user,public_key,timestamp,signature):
	if request.remote_addr in Banlist:
		abort(403)
	if len(user) != 52:
		abort(403)
	testing_address = address.keyToAddr2(public_key,user)
	if testing_address != user:
		abort(403)
	if testing_address in Banlist:
		abort(403)
	message = user + ":" + timestamp
	prove_ownership = messages.verify_message(public_key, signature, message)
	if prove_ownership == False:
		abort(403)
	if time.time() - float(timestamp) < 40:
		try:
			con = sql.connect("info.db", check_same_thread=False)
			con.text_factory = str
			con.row_factory = sql.Row
			cur = con.cursor()
			return_data = requests.get("http://127.0.0.1:12995/available/memory")
			result = return_data.content
			if result == "False":
				cur.execute('SELECT * FROM fakeAccounts WHERE identifier=?', (user,))
				result = cur.fetchall()
				if len(result) == 1:
					nonce = result[0]["proof_of_work"]
					if nonce == "POSTED" or nonce == None:
						word = generator.get()
						proofofwork = generator.hashed(word)
						time_generated = str(int(time.time()))
						cur.execute('UPDATE fakeAccounts SET hash=?, proof_of_work=?, proof_of_work_time=? WHERE identifier=?', (proofofwork,"None",time_generated,user))
						con.commit()
					else:
						time_generated = result[0]["proof_of_work_time"]
						if time_generated == "None" and nonce == "None":
							proofofwork = "None"
							time_generated = "None"
						else:
							if time.time() - float(time_generated) < 25:
								hashed = result[0]["hash"]
								return hashed + "," + time_generated
							else:
								word = generator.get()
								proofofwork = generator.hashed(word)
								time_generated = str(int(time.time()))
								cur.execute('UPDATE fakeAccounts SET hash=?, proof_of_work=?, proof_of_work_time=? WHERE identifier=?', (proofofwork,"None",time_generated,user))
								con.commit()
					return proofofwork + "," + time_generated
				else:
					abort(403)
			else:
				cur.execute('SELECT * FROM fakeAccounts WHERE identifier=?', (user,))
				result = cur.fetchall()
				if len(result) == 1:
					nonce = result[0]["proof_of_work"]
					if nonce == "POSTED" or nonce == "None":
						proofofwork = "None"
						time_generated = "None"
						cur.execute('UPDATE fakeAccounts SET hash=?, proof_of_work=?, proof_of_work_time=? WHERE identifier=?', ("None","None","None",user))
						con.commit()
					elif nonce == "None":
						proofofwork = "None"
						time_generated = "None"
					else:
						time_generated = result[0]["proof_of_work_time"]
						if time.time() - float(time_generated) < 25:
							return nonce + "," + time_generated
						else:
							proofofwork = "None"
							time_generated = "None"
							cur.execute('UPDATE fakeAccounts SET hash=?, proof_of_work=?, proof_of_work_time=? WHERE identifier=?', ("None","None","None",user))
							con.commit()
					return proofofwork + "," + time_generated
				else:
					abort(403)
				return "None,None"
		except:
			return "Something went wrong."
		finally:
			try:
				con.close()
			except:
				pass
	else:
		abort(403)

@app.route('/encrypt/post/<user>/<public_key>/<timestamp>/<signature>', methods=['POST'])
@limit_content_length(1 * 1024 * 1024)
def encryption_post(user,public_key,timestamp,signature):
	if request.remote_addr in Banlist:
		abort(403)
	if len(user) != 52:
		abort(403)
	testing_address = address.keyToAddr2(public_key,user)
	if testing_address != user:
		abort(403)
	if testing_address in Banlist:
		abort(403)
	message = user + ":" + timestamp
	prove_ownership = messages.verify_message(public_key, signature, message)
	if prove_ownership == False:
		abort(403)
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.text_factory = str
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM fake_account')
		result = cur.fetchall()
		fakeAccount = result[0]["fakeidentifier"]
		if fakeAccount == user:
			return "OK"
		cur.execute('SELECT * FROM fakeAccounts WHERE identifier=?', (user,))
		result = cur.fetchall()
		found = False
		if len(result) == 1:
			found = True
			time_generated = result[0]["time_generated"]
			if time.time() - float(time_generated) < 1750:
				abort(403)
		elif len(result) > 1:
			abort(403)
		if time.time() - float(timestamp) < 10:
			data = request.data
			data = decrypt.decryptfromPubKey(data)
			if data == False:
				abort(403)
			usersEncryptionKey = data
			if found == True:
				cur.execute('UPDATE fakeAccounts SET EncryptionKey=?, time_generated=? WHERE identifier=?', (usersEncryptionKey,str(int(time.time())),user))
				con.commit()
			else:
				cur.execute('INSERT INTO fakeAccounts (identifier,EncryptionKey,time_generated) VALUES (?,?,?)', (user,usersEncryptionKey,str(int(time.time()))))
				con.commit()
			return "OK"
	except:
		return "Something went wrong."
	finally:
		try:
			con.close()
		except:
			pass

@app.route('/data/new/<Identifier>/<public_key>/<timestamp>/<signature>/<hash>/<nonce>', methods=['POST'])
@limit_content_length(4 * 1024 * 1024)
@test_peers()
def data_new(Identifier,public_key,timestamp,signature,hash,nonce):
	if request.remote_addr in Banlist:
		abort(403)
	if len(Identifier) != 52:
		abort(403)
	testing_address = address.keyToAddr2(public_key,Identifier)
	if testing_address != Identifier:
		abort(403)
	if testing_address in Banlist:
		abort(403)
	message = Identifier + ":" + timestamp
	prove_ownership = messages.verify_message(public_key, signature, message)
	if prove_ownership == False:
		abort(403)
	if time.time() - float(timestamp) < 40:
		try:
			con = sql.connect("info.db", check_same_thread=False)
			con.row_factory = sql.Row
			cur = con.cursor()
			cur.execute('SELECT * FROM fakeAccounts WHERE identifier=?', (Identifier,))
			result = cur.fetchall()
			if len(result) == 1:
				payload = request.data
				EncryptionKey = result[0]["EncryptionKey"]
				Hash = result[0]["hash"]
				if Hash != str(hash):
					abort(403)
				ProofOfWorkTime = result[0]["proof_of_work_time"]
				ProofOfWork = result[0]["proof_of_work"]
				if Hash == "None" and ProofOfWorkTime == "None" and ProofOfWork == "None":
					cur.execute('UPDATE fakeAccounts SET proof_of_work=? WHERE identifier=?',("POSTED",Identifier))
					con.commit()
					payload = decrypt.decryptAES(EncryptionKey,payload)
					if payload != False:
						result = memory_new(Identifier,payload)
						if result == "Ban":
							check_ban = requests.get("http://127.0.0.1:12995/check/ban/"+Identifier+"/"+request.remote_addr)
							return "You have been banned! Bye!"
						else:
							return "Added"
					else:
						abort(403)
				else:
					if ProofOfWork == "POSTED":
						abort(403)
					if time.time() - float(ProofOfWorkTime) < 25 and time.time() - float(ProofOfWorkTime) > 5:
						result = proof_of_work.verify(hash,nonce)
						if result == False:
							abort(403)
						cur.execute('UPDATE fakeAccounts SET proof_of_work=? WHERE identifier=?',(nonce,Identifier))
						con.commit()
						payload = decrypt.decryptAES(EncryptionKey,payload)
						if payload != False:
							result = memory_new(Identifier,payload)
							if result == "Ban":
								check_ban = requests.get("http://127.0.0.1:12995/check/ban/"+Identifier+"/"+request.remote_addr)
								return "You have been banned! Bye!"
							else:
								return "Added"
						else:
							abort(403)
					else:
						abort(403)
			else:
				abort(403)
		except Exception as e:
			print e
			return "Something went wrong!"
		finally:
			try:
				con.close()
			except:
				pass
	else:
		abort(403)

@app.route('/tx/new', methods=['POST'])
def my_transactions_add():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		try:
			data = request.data
			con = sql.connect("info.db", check_same_thread=False)
			con.row_factory = sql.Row
			cur = con.cursor()
			details = data.split(",")
			tx_hash = details[0]
			timestamp = str(int(float(details[1])))
			cur.execute('INSERT INTO transactions (tx_hash,time) VALUES (?,?)', (tx_hash,timestamp))
			con.commit()
			return "Done"
		except:
			return "Something went wrong!"
		finally:
			try:
				con.close()
			except:
				pass
	else:
		abort(403)

@app.route('/data/pool/new', methods=['POST'])
def data_pool_new():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		try:
			data = request.data
			con = sql.connect("info.db", check_same_thread=False)
			con.row_factory = sql.Row
			cur = con.cursor()
			details = data.split(",")
			operation = details[0]
			sender = details[1]
			receiver = details[2]
			timestamp = str(int(float(details[3])))
			transaction_hash = details[8]
			cur.execute('INSERT INTO cache (sender,receiver,time,operation,tx_hash,data,status) VALUES (?,?,?,?,?,?,?)', (sender,receiver,timestamp,operation,transaction_hash,data,"PASS"))
			con.commit()
			return "Done"
		except:
			return "Something went wrong!"
		finally:
			try:
				con.close()
			except:
				pass
	else:
		abort(403)

@app.route('/tx/<tx>', methods=['GET'])
def check_transaction(tx):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		found = False
		try:
			con = sql.connect("info.db", check_same_thread=False)
			con.row_factory = sql.Row
			cur = con.cursor()
			cur.execute('SELECT * FROM transactions WHERE tx_hash=?', (tx,))
			result = cur.fetchall()
			if len(result) == 1:
				found = True
			return str(found)
		except:
			return "Something went wrong!"
		finally:
			try:
				con.close()
			except:
				pass
	else:
		abort(403)

@app.route('/get/nodes', methods=['GET'])
def get_nodes():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		result = ','.join(nodes)
		return result
	else:
		abort(403)

@app.route('/memory/search/<user>/<public_key>/<timestamp>/<signature>/<Identifier>/<Identifier_public_key>/<Identifier_signature>', methods=['GET'])
@test_peers()
def memory_search_user_alternative(user,public_key,timestamp,signature,Identifier,Identifier_public_key,Identifier_signature):
	final = "None"
	if request.remote_addr in Banlist:
		abort(403)
	testing_address = address.keyToAddr2(public_key,user)
	if testing_address != user:
		abort(403)
	if testing_address in Banlist:
		abort(403)
	message = user + ":" + timestamp
	prove_ownership = messages.verify_message(public_key,signature,message)
	if prove_ownership == False:
		abort(403)
	if time.time() - float(timestamp) < 10:
		try:
			con = sql.connect("info.db", check_same_thread=False)
			con.row_factory = sql.Row
			cur = con.cursor()
			cur.execute('SELECT * FROM fakeAccounts WHERE identifier=?', (user,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
				Identifier = decrypt.decryptAES(EncryptionKey,str(Identifier))
				if Identifier == False:
					abort(403)
				Identifier_signature = decrypt.decryptAES(EncryptionKey,str(Identifier_signature))
				if Identifier_signature == False:
					abort(403)
				Identifier_public_key = decrypt.decryptAES(EncryptionKey,str(Identifier_public_key))
				if Identifier_public_key == False:
					abort(403)
				testing_address = address.keyToAddr(Identifier_public_key,Identifier)
				if testing_address != Identifier:
					abort(403)
				if testing_address in Banlist:
					abort(403)
				message = Identifier + ":" + timestamp
				prove_ownership = messages.verify_message(Identifier_public_key,Identifier_signature,message)
				if prove_ownership == False:
					abort(403)
				cur.execute('SELECT * FROM cache WHERE receiver=? AND operation!=? AND status!=? ORDER BY time LIMIT 1', (Identifier,"OSP","PASS"))
				result = cur.fetchall()
				if len(result) == 1:
					tx_hash_output = result[0]["tx_hash"]
					final = result[0]["data"]
					final = encrypt.encryptAES(EncryptionKey,final)
					cur.execute('DELETE FROM cache WHERE tx_hash=? AND receiver=? AND operation!=?', (tx_hash_output,Identifier,"OSP"))
					con.commit()
				return final
			else:
				abort(403)
		except:
			return "Something went wrong!"
		finally:
			try:
				con.close()
			except:
				pass
	
	return final

@app.route('/memory/search/<user>/<public_key>/<timestamp>/<signature>/<Identifier>', methods=['GET'])
@test_peers()
def memory_search_user(user,public_key,timestamp,signature,Identifier):
	final = "None"
	if request.remote_addr in Banlist:
		abort(403)
	testing_address = address.keyToAddr2(public_key,user)
	if testing_address != user:
		abort(403)
	if testing_address in Banlist:
		abort(403)
	message = user + ":" + timestamp
	prove_ownership = messages.verify_message(public_key,signature,message)
	if prove_ownership == False:
		abort(403)
	if time.time() - float(timestamp) < 10:
		try:
			con = sql.connect("info.db", check_same_thread=False)
			con.row_factory = sql.Row
			cur = con.cursor()
			cur.execute('SELECT * FROM fakeAccounts WHERE identifier=?', (user,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
				Identifier = decrypt.decryptAES(EncryptionKey,str(Identifier))
				if Identifier == False:
					abort(403)
				cur.execute('SELECT * FROM cache WHERE receiver=? AND operation!=? AND status!=? ORDER BY RANDOM() LIMIT 1', (Identifier,"OSP","PASS"))
				result = cur.fetchall()
				if len(result) == 1:
					tx_hash_output = result[0]["tx_hash"]
					final = result[0]["data"]
					final = encrypt.encryptAES(EncryptionKey,final)
					if final == False:
						abort(403)
				return final
			else:
				abort(403)
		except:
			return "Something went wrong!"
		finally:
			try:
				con.close()
			except:
				pass
	
	return final

@app.route('/nodes/total', methods=['GET'])
def nodes_total():
	if request.remote_addr in Banlist:
		abort(403)
	result = 0
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM peers')
		result = cur.fetchall()
		result = len(result)
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass
	return str(result)

@app.route('/users/total', methods=['GET'])
def users_total():
	if request.remote_addr in Banlist:
		abort(403)
	result = 0
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM users')
		result = cur.fetchall()
		result = len(result)
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass
	return str(result)

@app.route('/users/online', methods=['GET'])
def users_online():
	if request.remote_addr in Banlist:
		abort(403)
	users_online_now = 0
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM users')
		results = cur.fetchall()
		for result in results:
			last_online = result["last_online"]
			if time.time() - float(last_online) <= 420:
				users_online_now += 1
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass
	return str(users_online_now)

@app.route('/available/memory', methods=['GET'])
def available_memory():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		try:
			memory = psutil.virtual_memory()
			available = memory[1]
			available = float(available) / float(1000000000)
			if available > 1:
				return "True"
			else:
				return "False"
		except:
			return "False"
	else:
		abort(403)

@app.route('/user/<user>', methods=['GET'])
def user_get(user):
	if request.remote_addr in Banlist:
		abort(403)
	if len(user) < 36 or len(user) > 50:
		abort(403)
	payload = "None"
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM users WHERE identifier=?', (user,))
		result = cur.fetchall()
		if len(result) == 1:
			payload = result[0]["payload"]
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass
	return payload

@app.route('/protocol/<protocol>', methods=['GET'])
def users_get(protocol):
	if request.remote_addr in Banlist:
		abort(403)
	if len(protocol) < 1 or len(protocol) > 50:
		abort(403)
	Payload = "None"
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM users WHERE protocols LIKE ?', ("%"+protocol+"%",))
		result = cur.fetchall()
		if len(result) > 1:
			Payload = ""
			for User in result:
				last_online = User["last_online"]
				if time.time() - float(last_online) < 600:
					payload = User["payload"]
					Payload += payload + "~"
			if Payload != "":
				Payload = Payload[:-1]
			elif payload == "":
				Payload = "None"
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass
	return Payload

@app.route('/ban/new', methods=['POST'])
def ban_new():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		try:
			con = sql.connect("info.db", check_same_thread=False)
			con.row_factory = sql.Row
			cur = con.cursor()
			Identifier = request.data
			cur.execute('SELECT * FROM banlist WHERE identifier=?', (Identifier,))
			banlist = cur.fetchall()
			if len(banlist) < 1:
				time_now = str(time.time())
				cur.execute('INSERT INTO banlist (identifier,time) VALUES (?,?)', (Identifier,time_now))
				con.commit()
				Banlist.append(Identifier)
		except:
			pass
		finally:
			try:
				con.close()
			except:
				pass
		return str("Done")
	else:
		abort(403)

@app.route('/check/ban/<identifier>/<peer>', methods=['GET'])
def check_ban(identifier,peer):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		try:
			con = sql.connect("info.db", check_same_thread=False)
			con.row_factory = sql.Row
			cur = con.cursor()
			cur.execute('SELECT * FROM banlist WHERE identifier=?', (identifier,))
			banlist = cur.fetchall()
			if len(banlist) > 0:
				cur.execute('UPDATE banlist SET peer=? WHERE identifier=?', (peer,identifier))
				con.commit()
				if peer not in Banlist:
					Banlist.append(peer)
				time_banned = banlist["time"]
				time_now = time.time()
				if time_now - float(time_banned) > 86400:
					result = False
				else:
					result = True
			else:
				result = False
		except:
			result = False
		finally:
			try:
				con.close()
			except:
				pass
	
		return str(result)
	else:
		abort(403)

def memory_new(identifier,payload):
	result = operations.check_payload(payload)
	result_details = result.split(",")
	account = result_details[0]
	result = result_details[1]
	if result == "True":
		try:			
			memory_post = requests.post("http://127.0.0.1:12995/memory/pool/new", data=payload)
			if memory_post.content == "Ban":
				ban_post = requests.post("http://127.0.0.1:12995/ban/new", data=identifier)
				return "Ban"
			else:
				return "Added"
		except:
			return "Error"
	elif result == "Received":
		return "Received"
	elif result == "pass":
		return "pass"
	else:
		ban_post = requests.post("http://127.0.0.1:12995/ban/new", data=identifier)
		return "Ban"

def ask_memory(account,peer):
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
		result = cur.fetchall()
		if len(result) == 1:
			user = result[0]["identifier"]
			cur.execute('SELECT * FROM fakeAccounts WHERE identifier=?', (user,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
			else:
				return
		else:
			return
		cur.execute('SELECT * FROM fake_account')
		accounts = cur.fetchall()
		Account = accounts[0]["fakeidentifier"]
		fake_private_key_hex = accounts[0]["fake_private_key_hex"]
		fake_public_key_hex = accounts[0]["fake_public_key_hex"]
		fake_Address = address.keyToAddr2(fake_public_key_hex, Account)
		timestamp = str(int(time.time()))
		signature = messages.sign_message(fake_private_key_hex, fake_Address+":"+timestamp)
		fake_signature = signature.encode("hex")
		cur.execute('SELECT * FROM accounts WHERE identifier=?', (account,))
		accounts = cur.fetchall()
		private_key_hex = accounts[0]["private_key_hex"]
		public_key_hex = accounts[0]["public_key_hex"]
		signature = messages.sign_message(private_key_hex, account+":"+timestamp)
		signature = signature.encode("hex")
		account = encrypt.encryptAES(EncryptionKey,account)
		public_key_hex = encrypt.encryptAES(EncryptionKey,public_key_hex)
		signature = encrypt.encryptAES(EncryptionKey,signature)
		if account == False or public_key_hex == False or signature == False:
			return
		ip_result = whatis(peer)
		if ip_result == False:
			return
		if ip_result == "4":
			return_data = requests.get("http://"+peer+":12995/memory/search/"+Account+"/"+fake_public_key_hex+"/"+timestamp+"/"+fake_signature+"/"+account+"/"+public_key_hex+"/"+signature)
		else:
			return_data = requests.get("http://["+peer+"]:12995/memory/search/"+Account+"/"+fake_public_key_hex+"/"+timestamp+"/"+fake_signature+"/"+account+"/"+public_key_hex+"/"+signature)
		if return_data.content != "None" and return_data.status_code == 200:
			payload = decrypt.decryptAES(EncryptionKey,return_data.content)
			if payload == False:
				return
			result = memory_new(user,payload)
			if result == "Added":
				print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] <- received data from " + peer
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass

def app_server():
	try:
		import platform
		machine = platform.system()
		print "[!] Trying to start Flask server"
		print "	[+] Flask server started!"
		if machine == "Linux" or machine == "Darwin":
			app.run(host='0.0.0.0', port=12995, threaded=True)
		else:
			app.run(host='127.0.0.1', port=12995, threaded=True)
	except (Exception,KeyboardInterrupt) as e:
		print e
		pass
	
def send_online_status():
	try:
		global accounts
		for account in accounts:
			online_status.online_status(account)
	except (Exception,KeyboardInterrupt):
		pass
				
def get_other_nodes():
	try:
		for connection in connections:
			connection_details = connection.split(",")
			account = connection_details[0]
			peer = connection_details[1]
			other_nodes.get(peer)
	except (Exception,KeyboardInterrupt):
		pass
	
def connected_nodes():
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		for GetFromSetting in GetFromSettings:
			account = GetFromSetting
			setting = GetFromSettings[account]
			if setting == "ALL":
				times_found = 0
				for connection in connections:
					connection_details = connection.split(",")
					Account = connection_details[0]
					if Account == account:
						times_found += 1
				if times_found < 16:
					cur.execute('SELECT * FROM peers ORDER BY RANDOM() LIMIT ' + str(16-times_found))
					peers = cur.fetchall()
					if len(peers) > 0:
						for peer in peers:
							found = False
							Peer = peer["peer"]
							Identifier = peer["identifier"]
							for connection in connections:
								connection_details = connection.split(",")
								ACCOUNT = connection_details[0]
								PEER = connection_details[1]
								if ACCOUNT == account and Peer == PEER:
									found = True
									break
							if found == False and Identifier not in accounts and Identifier not in Banlist:
								payload = account + "," + Peer
								connections.append(payload)
								print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] <- connected to node: " + Peer
			elif setting != "NONE":
				peers = setting.replace(" ","")
				peers = peers.split(",")
				for peer in peers:
					found = False
					for connection in connections:
						connection_details = connection.split(",")
						ACCOUNT = connection_details[0]
						PEER = connection_details[1]
						if ACCOUNT == account and Peer == PEER:
							found = True
							break
					if found == False:
						cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
						result = cur.fetchall()
						if len(result) == 1:
							payload = account + "," + peer
							connections.append(payload)
							print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] <- connected to node: " + peer
		for PostToSetting in PostToSettings:
			account = PostToSetting
			setting = PostToSettings[account]
			if setting == "ALL":
				times_found = 0
				for connection in PostTo:
					connection_details = connection.split(",")
					Account = connection_details[0]
					if Account == account:
						times_found += 1
				if times_found < 16:
					cur.execute('SELECT * FROM peers ORDER BY RANDOM() LIMIT ' + str(16-times_found))
					peers = cur.fetchall()
					if len(peers) > 0:
						for peer in peers:
							found = False
							Identifier = peer["identifier"]
							Peer = peer["peer"]
							for connection in PostTo:
								connection_details = connection.split(",")
								ACCOUNT = connection_details[0]
								PEER = connection_details[1]
								if ACCOUNT == account and Peer == PEER:
									found = True
									break
							if found == False and Identifier not in accounts and Identifier not in Banlist:
								payload = account + "," + Peer
								PostTo.append(payload)
								print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] -> connected to node: " + Peer
			elif setting != "NONE":
				peers = setting.replace(" ","")
				peers = peers.split(",")
				for peer in peers:
					found = False
					for connection in PostTo:
						connection_details = connection.split(",")
						ACCOUNT = connection_details[0]
						PEER = connection_details[1]
						if ACCOUNT == account and Peer == PEER:
							found = True
							break
					if found == False:
						cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
						result = cur.fetchall()
						if len(result) == 1:
							payload = account + "," + peer
							PostTo.append(payload)
							print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] -> connected to node: " + peer
	except (Exception,KeyboardInterrupt):
		pass
	finally:
		try:
			con.close()
		except:
			pass
	
def ask_for_new_data():
	try:
		for connection in connections:
			connection_details = connection.split(",")
			account = connection_details[0]
			peer = connection_details[1]
			ask_memory(account,peer)
	except (Exception,KeyboardInterrupt):
		pass

def daemon_data():
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
	except:
		pass
	while True:
		try:
			cur.execute('SELECT * FROM cache')
			data_to_check = cur.fetchall()
			for data_check in data_to_check:
				timestamp = data_check["time"]
				tx_hash = data_check["tx_hash"]
				if time.time() - float(timestamp) > 600:
					cur.execute('DELETE FROM cache WHERE tx_hash=?', (tx_hash,))
					con.commit()
		except:
			pass

		try:
			cur.execute('SELECT * FROM transactions')
			data_to_check = cur.fetchall()
			for data_check in data_to_check:
				timestamp = data_check["time"]
				transaction = data_check["tx_hash"]
				if time.time() - float(timestamp) > 1800:
					cur.execute('DELETE FROM transactions WHERE tx_hash=?', (transaction,))
					con.commit()
		except:
			pass

		time.sleep(60)

def daemon():
	daemon_data_enabled = False
	Last_check = 0
	Last_online = 0
	Last_search = 0
	Last_peers_check = 0
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
	except:
		pass
	while True:
		try:
			cur.execute('SELECT * FROM keys')
			results = cur.fetchall()
			if len(results) > 0:
				checks = 0
				while checks < len(results):
					time_now = time.time()
					timestamp = results[checks]["time_generated"]
					if time_now - float(timestamp) > 900:
						cur.execute('DELETE FROM keys WHERE time_generated=?', (timestamp,))
						con.commit()
					checks += 1
		except:
			pass

		try:
			cur.execute('SELECT * FROM encryption_key')
			results = cur.fetchall()
			if len(results) == 1:
				checks = 0
				while checks < len(results):
					time_now = time.time()
					timestamp = results[checks]["time_generated"]
					if time_now - float(timestamp) > 1800 and time_now - float(timestamp) < 1900:
						private_key_generated,public_key_generated = keys.generate_encryption_key()
						cur.execute('INSERT INTO encryption_key (public_key,private_key,time_generated) VALUES (?,?,?)', (public_key_generated,private_key_generated,str(int(time.time()))))
						con.commit()
						cur.execute('DELETE FROM encryption_key WHERE time_generated=?', (timestamp,))
						con.commit()
					checks += 1
			else:
				private_key_generated,public_key_generated = keys.generate_encryption_key()
				cur.execute('INSERT INTO encryption_key (public_key,private_key,time_generated) VALUES (?,?,?)', (public_key_generated,private_key_generated,str(int(time.time()))))
				con.commit()
		except:
			pass

		try:
			cur.execute('SELECT * FROM test_peers')
			results = cur.fetchall()
			for result in results:
				peer = result["peer"]
				cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
				result = cur.fetchall()
				if len(result) == 0:
					identifier.get(peer)
				cur.execute('DELETE FROM test_peers WHERE peer=?', (peer,))
				con.commit()
		except:
			pass
		
		if time.time() - Last_peers_check > 300:
			try:
				cur.execute('SELECT * FROM peers')
				results = cur.fetchall()
				for result in results:
					peer = result["peer"]
					identifier.get(peer)
				for node in nodes:
					cur.execute('SELECT * FROM peers WHERE peer=?', (node,))
					result = cur.fetchall()
					if len(result) == 0:
						identifier.get(node)
				Last_peers_check = time.time()
			except:
				pass

		try:
			for connection in connections:
				connection_details = connection.split(",")
				account = connection_details[0]
				peer = connection_details[1]
				cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
				result = cur.fetchall()
				if len(result) == 0:
					connections.remove(connection)
					print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] X disconnected from node: " + peer
				else:
					Identifier = result[0]["identifier"]
					if Identifier in Banlist:
						print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+Identifier+"] banned"
						cur.execute('DELETE FROM peers WHERE identifier=?', (Identifier,))
						con.commit()
			for connection in PostTo:
				connection_details = connection.split(",")
				account = connection_details[0]
				peer = connection_details[1]
				cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
				result = cur.fetchall()
				if len(result) == 0:
					PostTo.remove(connection)
					print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] X disconnected from node: " + peer
				else:
					Identifier = result[0]["identifier"]
					if Identifier in Banlist:
						print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+Identifier+"] banned"
						cur.execute('DELETE FROM peers WHERE identifier=?', (Identifier,))
						con.commit()
		except:
			pass
		
		try:
			for account in accounts:
				cur.execute('SELECT * FROM keys WHERE identifier=? ORDER BY time_generated DESC LIMIT 1', (account,))
				results = cur.fetchall()
				if len(results) > 0:
					last_generated = results[0]["time_generated"]
					if time.time() - float(last_generated) >= 300:
						priv_key,pub_key = keys.generate()
						time_now = time.time()
						cur.execute('INSERT INTO keys (identifier,public_key,private_key,time_generated) VALUES (?,?,?,?)', (account,pub_key,priv_key,str(time_now)))
						con.commit()
				else:
					priv_key,pub_key = keys.generate()
					time_now = time.time()
					cur.execute('INSERT INTO keys (identifier,public_key,private_key,time_generated) VALUES (?,?,?,?)', (account,pub_key,priv_key,str(time_now)))
					con.commit()
		except:
			pass

		try:
			cur.execute('SELECT * FROM banlist')
			results = cur.fetchall()
			if len(results) > 0:
				checks = 0
				while checks < len(results):
					time_now = time.time()
					banned_user = results[checks]["identifier"]
					banned_peer = results[checks]["peer"]
					timestamp = results[checks]["time"]
					if time_now - float(timestamp) > 86400:
						cur.execute('DELETE FROM banlist WHERE time=?', (timestamp,))
						con.commit()
						if banned_user in Banlist:
							Banlist.remove(banned_user)
						if banned_peer in Banlist:
							Banlist.remove(banned_peer)
					checks += 1
		except:
			pass

		try:
			cur.execute('SELECT * FROM last_posts')
			results = cur.fetchall()
			if len(results) > 0:
				checks = 0
				while checks < len(results):
					time_now = time.time()
					tx_hash = results[checks]["tx_hash"]
					timestamp = results[checks]["time"]
					if time_now - float(timestamp) > 1800:
						cur.execute('DELETE FROM last_posts WHERE time=? AND tx_hash=?', (timestamp,tx_hash))
						con.commit()
					checks += 1
		except:
			pass

		try:
			cur.execute('SELECT * FROM cache WHERE status=?', ("PASS",))
			result = cur.fetchall()
			if len(result) > 0:
				peers_to_post = []
				for connection in PostTo:
					connection_details = connection.split(",")
					peer = connection_details[1]
					if peer not in peers_to_post:
						peers_to_post.append(peer)
				for data_to_post in result:
					data_to_post = data_to_post["data"]
					if len(PostTo) > 0:
						for peer in peers_to_post:
							data_to_post_details = data_to_post.split(",")
							tx_hash = data_to_post_details[8]
							cur.execute('SELECT * FROM last_posts WHERE tx_hash=? AND peer=?', (tx_hash,peer))
							result = cur.fetchall()
							if len(result) == 0:
								new_data.new_data(peer,data_to_post)
								cur.execute('INSERT INTO last_posts (peer,tx_hash,time) VALUES (?,?,?)', (peer,tx_hash,str(int(time.time()))))
								con.commit()
						cur.execute('DELETE FROM cache WHERE tx_hash=?', (tx_hash,))
						con.commit()
		except Exception as e:
			print e
			pass

		if daemon_data_enabled == False:
			thread.start_new_thread(daemon_data,())
			daemon_data_enabled = True

		if time.time() - Last_check > 60:
			connected_nodes()
			get_other_nodes()
			Last_check = time.time()
		if time.time() - Last_online > 300:
			send_online_status()
			Last_online = time.time()
		if time.time() - Last_search > 2:
			ask_for_new_data()
			Last_search = time.time()


thread.start_new_thread(daemon,())
app_server()
