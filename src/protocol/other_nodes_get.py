import sqlite3 as sql

def get():
	try:
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM peers ORDER BY RANDOM() LIMIT 16')
		response = ""
		peers = cur.fetchall()
		for peer in peers:
			response += peer["peer"] + ","
		if response != "" and response[-1] == ",":
			response = response[:-1]
		if response == "":
			response = None
		con.close()
		return response
	except:
		return "DB error"
