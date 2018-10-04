import string
import random
from hashlib import sha256

def get(size=32, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))

def hashed(Word):
	return sha256(Word.rstrip()).hexdigest()
