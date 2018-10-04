import socket
from src.cryptography import address, messages, encrypt, decrypt
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

def get(peer):
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		result = whatis(peer)
		if result == False:
			cur.execute('DELETE FROM peers WHERE peer=?', (peer,))
			con.commit()
			return
		if result == "4":
			return_data = requests.get("http://"+peer+":12995/other/nodes")
		else:
			return_data = requests.get("http://["+peer+"]:12995/other/nodes")
		if return_data.content != "None":
			nodes = return_data.content.split(",")
			for node in nodes:
				cur.execute('SELECT * FROM test_peers WHERE peer=?', (node,))
				result = cur.fetchall()
				if len(result) == 0:
					cur.execute('INSERT INTO test_peers (peer) VALUES (?)', (node,))
					con.commit()
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass
