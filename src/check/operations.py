from src.cryptography import messages, address
from hashlib import sha256
import time
import requests

def check_payload(payload):
	details = payload.split(",")
	if len(details) == 10:
		operation = details[0]
		sender = details[1]
		sender = sender.split("|")
		senders_count = len(sender)
		receiver = details[2]
		receiver = receiver.split("|")
		receivers_count = len(receiver)
                additional3 = details[6]
		additional3 = additional3.split("|")
		pkeys_count = len(additional3)
		if senders_count == receivers_count:
			if receivers_count == pkeys_count:
				if pkeys_count > 10:
					return "Just" + "," + "pass"
				if pkeys_count > 1 and operation == "OSP":
					return "Just" + "," + "pass"
				for Sender in sender:
					Address = ""
					for Additional3 in additional3:
						Address = address.keyToAddr(Additional3,Sender)
						if Address == Sender:
							break
					if Address != Sender:
						return "Just" + "," + "pass"
					if len(Sender) < 36 or len(Sender) > 50:
						return "Just" + "," + "pass"
				if len(sender) == 1:
					sender = sender[0]
				else:
					sender = '|'.join(sender)
				if len(additional3) == 1:
					additional3 = additional3[0]
				else:
					additional3 = '|'.join(additional3)
				for Receiver in receiver:
					if len(Receiver) < 36 or len(Receiver) > 50:
						return "Just" + "," + "pass"
				if len(receiver) == 1:
					receiver = receiver[0]
				else:
					receiver = '|'.join(receiver)
			else:
				return "Just" + "," + "pass"
		else:
			return "Just" + "," + "pass"
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
			if pkeys_count == 1:
				prove_ownership = messages.verify_message(additional3, signature, final)
			else:
				prove_ownership = True
			if prove_ownership == True:
				result = requests.get("http://127.0.0.1:12995/tx/"+TX_hash)
				result = result.content
				if result == "False":
					requests.post("http://127.0.0.1:12995/tx/new", data=transaction_hash+","+timestamp)
					return sender + "," + "True"
				else:
					return sender + "," + "Received"
			else:
				return sender + "," + False
		else:
			return sender + "," + False
	else:
		return sender + "," + False
