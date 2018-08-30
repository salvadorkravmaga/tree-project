import sqlite3
from sqlite3 import Error

global conn
 
def create(path,name):
	try:
		filename = str(path + name)
        	conn = sqlite3.connect(filename)
    	except Error as e:
        	print(e)
	finally:
		try:
			conn.close()
		except:
			pass
	
