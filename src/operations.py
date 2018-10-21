from src.cryptography import messages, address
from hashlib import sha256
import time
import requests

def check_payload(payload):
	details = payload.split(",")
	if len(details) == 10:
		operation = details[0]
		sender = details[1]
		receiver = details[2]
                additional3 = details[6]
                Address = address.keyToAddr(additional3,sender)
                if Address != sender:
			return sender + "," + False
		if len(sender) < 36 or len(receiver) < 36 or len(sender) > 50 or len(receiver) > 50:
			return sender + "," + False
		timestamp = str(int(float(details[3])))
		time_now = time.time()
		additional1 = details[4]
		additional2 = details[5]
		data = details[7]
		transaction_hash = details[8]
		final = operation + ":" + sender + ":" + receiver + ":" + str(timestamp) + ":" + additional1 + ":" + additional2 + ":" + additional3 + ":" + data
		TX_hash = sha256(final.rstrip()).hexdigest()
		if TX_hash == transaction_hash:
			signature = details[-1]
			final = TX_hash
			prove_ownership = messages.verify_message(additional3, signature, final)
			if prove_ownership == True:
				result = requests.get("http://127.0.0.1:12995/tx/"+TX_hash)
				result = result.content
				if result == "False":
					requests.post("http://127.0.0.1:12995/tx/new", data=transaction_hash)
					return sender + "," + "True"
				else:
					return sender + "," + "Received"
			else:
				return sender + "," + False
		else:
			return sender + "," + False
	else:
		return sender + "," + False
