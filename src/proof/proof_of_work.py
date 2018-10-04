from hashlib import sha256
import time

def solve(Hash, Time):
	found = False
	i = 1
	while found == False:
		test_hash = sha256((Hash + str(i)).rstrip()).hexdigest()
		if test_hash[:4] == "0000":
			if time.time() - float(Time) < 25:
				time_passed = False
				while time.time() - float(Time) < 5:
					pass
				return str(i)
			else:
				return False
		i += 1

def verify(Hash, nonce):
	test_hash = sha256((Hash + str(nonce)).rstrip()).hexdigest()
	if test_hash[:4] == "0000":
		return True
	else:
		return False
