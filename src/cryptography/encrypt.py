from Crypto.PublicKey import RSA
from base64 import *
import sqlite3 as sql
import requests
import os

def encrypt(public_key,message):
	try:
		publicKey = public_key
		publicKey = RSA.importKey(publicKey,None)
		text = message
		enc=publicKey.encrypt(text,None)[0]
		encb64 = encodestring(enc)
		encb64 = encb64.replace("\n","")
		return encb64
	except:
		return False
