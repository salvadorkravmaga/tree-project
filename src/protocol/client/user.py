from src.cryptography import address, messages
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

def get(peer,user):
	try:
		return_data = requests.get("http://"+peer+":12995/user/"+user)
		if return_data.content != "None" and return_data.status == 200:
			return Identifier,return_data.content
		else:
			return False,False
	except:
		return False,False
	finally:
		try:
			con.close()
		except:
			pass
