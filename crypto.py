#!/usr/bin/env python
'''Crypto tastic

Usage:
  crypto.py en FILE [-o FILE]
  crypto.py de FILE [-o FILE]
  crypto.py (-h | --help)
  crypto.py --version

Options:
  -o FILE       Specify output file [default: ./test.txt]
  -h --help     Show this screen.
  --version     Show version.

'''
import sys, os, pickle, hashlib
from docopt import docopt
from Crypto.Cipher import AES
from cStringIO import StringIO
from Crypto import Random
from getpass import getpass

class C:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def read_in_chunks(file_object, chunk_size=1024):
	'''Lazy function (generator) to read a file piece by piece.
	Default chunk size: 1k.'''
	while True:
		data = file_object.read(chunk_size)
		if data:
			yield data
		else:
			break

def fail(msg):
	print C.FAIL + msg + C.ENDC
	sys.exit(1)

def fopen(name, perm):
	try:
		return open(name, perm)
	except IOError as e:
		fail('I/O error({0}): {1}'.format(e.errno, e.strerror))

def encrypt(iv, key, message):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.encrypt(message)

def decrypt(iv, key, message):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.decrypt(message)

def normalize(s):
	while len(s) < 16:
		s += u'\u0000'
	return s

def hash(msg):
	return hashlib.new('ripemd160', msg).digest()

def crypto(args):
	f = fopen(args['FILE'], 'rb')
	pass1 = getpass('Enter your password: ')
	if args['en']:
		size = os.path.getsize(args['FILE'])
		pass2 = getpass('Confirm your password: ')
		if pass1 == pass2:
			key = normalize(pass1)
		else:
			fail('Password does not match')
		message = b''
		iv = Random.new().read(AES.block_size)
		for piece in read_in_chunks(f, 16):
			piece = normalize(piece)
			message += encrypt(iv, key, piece)
		obj = {
			'iv': iv,
			'size': size,
			'message': message,
			'hash': hash(pass1)
		}
		o = fopen(args['-o'], 'wb')
		pickle.dump(obj, o)
	elif args['de']:
		obj = pickle.load(f)
		print len(obj['hash'])
		if hash(pass1) == obj['hash']:
			key = normalize(pass1)
			msgIO = StringIO(obj['message'])
			message = b''
			for piece in read_in_chunks(msgIO, 16):
				message += decrypt(obj['iv'], key, piece)
			o = fopen(args['-o'], 'wb')
			o.write(message[:obj['size']])
		else:
			fail('Incorrect password.')

if __name__ == '__main__':
	args = docopt(__doc__, version='Crypto 0.0.1')
	crypto(args)