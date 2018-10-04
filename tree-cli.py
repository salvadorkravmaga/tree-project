from src.cryptography import address, messages, keys
import sys
import os, os.path
import sqlite3 as sql
import requests
import socket
import time

try:
	con = sql.connect("info.db")
	con.row_factory = sql.Row
	cur = con.cursor()
except Exception as e:
	print e
	sys.exit(1)

def help():
	print "Tree daemon calls\n"
	print "-status 	Returns daemon's status"
	print "-usersonline	Returns online users in the network in the last 30 minutes"
	print "-whoami		Returns the account's identifier"
	print "-newaccount	Creates new account"
	print "-importprivkey	Imports private key"
	print "-exportprivkey	Exports private key"
	print "-importfake	Imports fake private key"
	print "-exportfake	Exports fake private key"
	print "-deleteaccount	Deletes a specific account"
	print "-clean		Deletes all accounts and encryption keys"

def status():
	try:
		request = requests.get("http://127.0.0.1:12995")
		server_running = True
	except:
		server_running = False

	if server_running == True:
		print "Daemon is running."
	else:
		print "Daemon is not running."

def usersonline():
	try:
		cur.execute('SELECT * FROM users')
		results = cur.fetchall()
		online = 0
		if len(results) > 0:
			checks = 0
			while checks < len(results):
				time_now = time.time()
				timestamp = results[checks]["last_online"]
				if time_now - float(timestamp) < 1800:
					online += 1
				checks += 1
		print "Users online: " + str(online)
	except Exception as e:
		print e
	con.close()

def whoami():
	try:
		cur.execute('SELECT * FROM accounts')
		results = cur.fetchall()
		for account in results:
			public_key_hex = account["public_key_hex"]
			Accountaddress = address.keyToAddr(public_key_hex)
			print "[+] " + Accountaddress
	except Exception as e:
		print e
	con.close()

def newaccount():
	print "[!] Generating new account"
	private_key_hex,public_key_hex,Accountaddress = address.generate_account()
	try:
		cur.execute('INSERT INTO accounts (identifier,private_key_hex,public_key_hex) VALUES (?,?,?)', (Accountaddress,private_key_hex,public_key_hex))
		con.commit()
	except:
		print "	[-] DB error. Exiting.."
		sys.exit(1)

	try:
		priv_key,pub_key = keys.generate()
	except:
		print "	[-] Error generating private/public keys pair. Exiting.."
		sys.exit(1)

	try:
		cur.execute('INSERT INTO keys (identifier,public_key,private_key,time_generated) VALUES (?,?,?,?)', (Accountaddress,pub_key,priv_key,str(time.time())))
		con.commit()
	except:
		print "	[-] DB error. Exiting.."
		sys.exit(1)

	print "	[+] New account " + Accountaddress + " created"

def importprivkey():
	private_key_hex = raw_input("Enter private key in hex format: ")
	public_key_hex, Address = address.details_from_private(private_key_hex)
	signature = messages.sign_message(private_key_hex,"test")
	prove_ownership = messages.verify_message(public_key_hex, signature.encode("hex"), "test")
	if prove_ownership == True:
		try:
			cur.execute('INSERT INTO accounts (identifier,private_key_hex,public_key_hex) VALUES (?,?,?)', (Address,private_key_hex,public_key_hex))
			con.commit()
			print "[+] Account " + Address + " added"
		except Exception as e:
			print e
		con.close()
	else:
		print "This private key does not prove ownership of " + Address

def importfake():
	private_key_hex = raw_input("Enter private key in hex format: ")
	public_key_hex, Address = address.details_from_private_fake(private_key_hex)
	signature = messages.sign_message(private_key_hex,"test")
	prove_ownership = messages.verify_message(public_key_hex, signature.encode("hex"), "test")
	if prove_ownership == True:
		cur.execute('SELECT * FROM fake_account')
		result = cur.fetchall()
		if len(result) == 0:
			try:
				cur.execute('INSERT INTO fake_account (fakeidentifier,fake_private_key_hex,fake_public_key_hex) VALUES (?,?,?)', (Address,private_key_hex,public_key_hex))
				con.commit()
				print "[+] Account " + Address + " added"
			except Exception as e:
				print e
		else:
			print "Another fake account already exists. Exiting.."
		con.close()
	else:
		print "This private key does not prove ownership of " + Address

def exportprivkey():
	try:
		account = raw_input("Account name: ")
		cur.execute('SELECT * FROM accounts WHERE identifier=?', (account,))
		accounts = cur.fetchall()
		if len(accounts) > 0:
			if len(accounts) == 1:
				private_key_hex = accounts[0]["private_key_hex"]
				print "[+] Private key (HEX): " + private_key_hex
		else:
			print "No account found"
	except Exception as e:
		print e
	con.close()

def exportfake():
	try:
		cur.execute('SELECT * FROM fake_account')
		accounts = cur.fetchall()
		if len(accounts) == 1:
			private_key_hex = accounts[0]["fake_private_key_hex"]
			print "[+] Private key (HEX): " + private_key_hex
		else:
			print "No account found"
	except Exception as e:
		print e
	con.close()

def deleteaccount():
	account = raw_input("Account to delete: ")
	try:
		cur.execute('DELETE FROM accounts WHERE identifier=?', (account,))
		con.commit()
		print "[+] Account " + account + " deleted"
	except Exception as e:
		print e
	con.close()

def clean():
	try:
		cur.execute('DELETE FROM accounts')
		con.commit()
		cur.execute('DELETE FROM keys')
		con.commit()
	except Exception as e:
		print e
	print "Done"
	con.close()

def main(arguments):
	if "-h" in arguments:
		help()
	else:
		if "-status" in arguments:
			status()
		elif "-usersonline" in arguments:
			usersonline()
		elif "-whoami" in arguments:
			whoami()
		elif "-newaccount" in arguments:
			newaccount()
		elif "-importprivkey" in arguments:
			importprivkey()
		elif "-exportprivkey" in arguments:
			exportprivkey()
		elif "-importfake" in arguments:
			importfake()
		elif "-exportfake" in arguments:
			exportfake()
		elif "-deleteaccount" in arguments:
			deleteaccount()
		elif "-clean" in arguments:
			clean()
		else:
			print "Unrecognized command."

if __name__ == "__main__":
	if sys.argv[1:] == []:
		help()
	else:
		main(sys.argv[1:])
