#!/usr/bin/env python
'''Crypto tastic

Usage:
  crypto.py en FILE [-o FILE] [--dropbox]
  crypto.py de FILE [-o FILE] [--dropbox]
  crypto.py de [-o FILE] --dropbox
  crypto.py (-h | --help)
  crypto.py --version

Options:
  -o FILE       Specify output file [default: ./out.crypto]
  -h --help     Show this screen.
  --version     Show version.

'''
import sys, os, hashlib
from docopt import docopt
from Crypto.Cipher import AES
from Crypto import Random
from getpass import getpass
from dropbox import client, rest

BS = AES.block_size

class C:
    HEADER = '\033[95m'
    OKB = '\033[94m'
    OKG = '\033[92m'
    WARN = '\033[93m'
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

def LOG(msg, COLOR=C.OKB):
	print COLOR + msg + C.ENDC

def fail(msg):
	LOG(msg, C.FAIL)
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

pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

def hash(msg):
	return hashlib.new('ripemd160', msg).digest()

TOKEN_FILE = "token_store.txt"
token = 'RCzUIPNfK-0AAAAAAAAAASL3XaO6aQryvrJ9CECVHbN1d7E2lerM8sObRF8X5Dmm'
BIG_FILE_TRESHOLD = 400000
def uploadToDropbox(encrypted, fname, override=True):
	fsize = os.path.getsize(encrypted)
	fileHandle = open(encrypted, 'rb')
	api_client = client.DropboxClient(token)
	if (fsize > BIG_FILE_TRESHOLD):
		chunkedUploadDropbox(fileHandle, fname, fsize, api_client)
		return
	# token = open(TOKEN_FILE).read()
	response = api_client.put_file("/" + fname + ".crypto", fileHandle, override)
	print response

def size_fmt(num):
    for x in ['bytes','kB','MB','GB','TB']:
        if num < 1000:
            return "{0:3.1f}{1}".format(num, x)
        num /= 1000.0

def chunkedUploadDropbox(handle, fname, size, client):
	offset = 0
	retry_attempt = 0
	length = 100000
	LOG('Uploading {0} in {1} chunks'.format(size_fmt(size), size_fmt(length)))
	while offset < size:
		try:
			client.upload_chunk(handle, length, offset)
			LOG('{:.1%}'.format(offset / float(size)), '')
			offset += length
		except rest.ErrorResponse as e:
			print e
			retry_attempt += 1
			LOG('Error; retry #' + str(retry_attempt), C.WARN)
			pass
		except rest.RESTSocketError:
			fail('Could not connect to dropbox.com')
	LOG('SUCCESS', C.OKG)

def getDropboxFile(fname):
	handle = open("." + fname + ".tmp", "wb")
	api_client = client.DropboxClient(token)
	f = api_client.get_file("/" + fname + ".crypto")
	handle.write(f.read())
	handle.close()
	return "." + fname + ".tmp"

def crypto(args):
	fname = args['FILE']
	outfile = args['-o']	
	if args['de'] and args['--dropbox']:
		outfile = fname
		fname = getDropboxFile(fname)
	f = fopen(fname, 'rb')
	pass1 = getpass('Enter your password: ')
	if args['en']:
		size = os.path.getsize(args['FILE'])
		pass2 = getpass('Confirm your password: ')
		if pass1 == pass2:
			key = pad(pass1)
		else:
			fail('Password does not match')
		LOG('ENCRYPTION...')
		message = b''
		iv = Random.new().read(BS)
		for piece in read_in_chunks(f, 16):
			if (len(piece) < BS):
				piece = pad(piece)
			message += encrypt(iv, key, piece)
		obj = {
			'iv': iv,
			'size': size,
			'message': message,
			'hash': hash(pass1)
		}
		o = fopen(outfile, 'wb')
		h = hash(pass1)
		pack = iv + h + message
		LOG('SUCCESS', C.OKG)
		o.write(pack)
		o.close()
		if args['--dropbox']:
			uploadToDropbox(outfile, fname)
			os.remove(outfile)
	elif args['de']:
		data = f.read(BS+20)
		iv = data[:BS]
		h = data[BS:BS+20]
		if hash(pass1) == h:
			key = pad(pass1)
			message = b''
			for piece in read_in_chunks(f, 16):
				message += decrypt(iv, key, piece)
			o = fopen(outfile, 'wb')
			o.write(unpad(message))
			if args['--dropbox']:
				os.remove(fname)
		else:
			fail('Incorrect password.')

if __name__ == '__main__':
	args = docopt(__doc__, version='0.0.1')
	crypto(args)