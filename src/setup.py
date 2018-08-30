from src.database import db, structure
import os

def config(path):
	try:
		db.create(os.path.join(path, ''),"info.db")
		structure.main(os.path.join(path,"info.db"),os.path.join(path, ''))
		return True
	except:
		return False
