import sqlite3
from sqlite3 import Error

def connection(filename):
    	try:
		filename = str(filename)
        	conn = sqlite3.connect(filename)
        	return conn
    	except Error as e:
        	print(e)
 
    	return None

def create(conn, sql_code):
    	try:
        	c = conn.cursor()
        	c.execute(sql_code)
    	except Error as e:
        	print(e)
	finally:
		c.close()

def main(db_file_path, folder_path):
	conn = connection(db_file_path)
	try:
		if conn is not None:
			structure = open(folder_path+"db.sql", "r").read()
			if "NEW_TABLE" in structure:
				structure = structure.split("NEW_TABLE")
				for sql_code in structure:
					create(conn, sql_code)
			else:
				create(conn, structure)
		else:
			print("Error! cannot create the database connection.")
	except Exception as e:
		print e
		pass
	finally:
		try:
			conn.close()
		except:
			pass

