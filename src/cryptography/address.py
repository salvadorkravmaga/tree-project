import os
import ecdsa
import hashlib
import base58

def details_from_private_fake(s):
	private_key = s
	sk = ecdsa.SigningKey.from_string(private_key.decode("hex"), curve = ecdsa.SECP256k1)
	vk = sk.verifying_key
	public_key = (vk.to_string()).encode("hex")
	ripemd160 = hashlib.new('ripemd160')
	ripemd160.update(hashlib.sha256(public_key).digest())
	middle_man = ripemd160.digest()
	checksum = hashlib.sha256(hashlib.sha256(middle_man).digest()).digest()[:18]
	binary_addr = middle_man + checksum
	addr = base58.b58encode(binary_addr)
	return public_key,addr

def details_from_private(s):
	private_key = s
	sk = ecdsa.SigningKey.from_string(private_key.decode("hex"), curve = ecdsa.SECP256k1)
	vk = sk.verifying_key
	public_key = (vk.to_string()).encode("hex")
	ripemd160 = hashlib.new('ripemd160')
	ripemd160.update(hashlib.sha256(public_key).digest())
	middle_man = ripemd160.digest()
	checksum = hashlib.sha256(hashlib.sha256(middle_man).digest()).digest()[:7]
	binary_addr = middle_man + checksum
	addr = base58.b58encode(binary_addr)
	return public_key,addr

def keyToAddr2(s,address):
	public_key = s
	ripemd160 = hashlib.new('ripemd160')
	ripemd160.update(hashlib.sha256(public_key).digest())
	middle_man = ripemd160.digest()
	checksum = hashlib.sha256(hashlib.sha256(middle_man).digest()).digest()[:18]
	binary_addr = middle_man + checksum
	addr = base58.b58encode(binary_addr)
	return addr

def keyToAddr(s,address):
	public_key = s
	ripemd160 = hashlib.new('ripemd160')
	ripemd160.update(hashlib.sha256(public_key).digest())
	middle_man = ripemd160.digest()
	starting = 7
	while starting < 16:
		checksum = hashlib.sha256(hashlib.sha256(middle_man).digest()).digest()[:starting]
		binary_addr = middle_man + checksum
		addr = base58.b58encode(binary_addr)
		if addr == address:
			break
		starting += 1
	return addr

def generate_fakeIdentifier():
	fake_private_key = os.urandom(32).encode("hex")
	sk = ecdsa.SigningKey.from_string(fake_private_key.decode("hex"), curve = ecdsa.SECP256k1)
	private_key = (sk.to_string()).encode("hex")
	vk = sk.verifying_key
	public_key = (vk.to_string()).encode("hex")
	ripemd160 = hashlib.new('ripemd160')
	ripemd160.update(hashlib.sha256(public_key).digest())
	middle_man = ripemd160.digest()
	checksum = hashlib.sha256(hashlib.sha256(middle_man).digest()).digest()[:18]
	binary_addr = middle_man + checksum
	fake = base58.b58encode(binary_addr)
	return private_key,public_key,fake

def generate_account():
	private_key = os.urandom(32).encode("hex")
	sk = ecdsa.SigningKey.from_string(private_key.decode("hex"), curve = ecdsa.SECP256k1)
	private_key = (sk.to_string()).encode("hex")
	vk = sk.verifying_key
	public_key = (vk.to_string()).encode("hex")
	ripemd160 = hashlib.new('ripemd160')
	ripemd160.update(hashlib.sha256(public_key).digest())
	middle_man = ripemd160.digest()
	checksum = hashlib.sha256(hashlib.sha256(middle_man).digest()).digest()[:7]
	binary_addr = middle_man + checksum
	addr = base58.b58encode(binary_addr)
	return private_key,public_key,addr
