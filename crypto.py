# todo:
# - rewrite into a class [in progress]
# - test for path stuff
# - deal with dropbox token stuff
# - comments, code quality
# - directory
# - work on chunked uploader (code, other stuff from dropbox)
# - think of a name
# - think about integrating with aes.py as an edge thing
# - look into global publishing (like pip binds itself globally)

#!/usr/bin/env python
'''Crypto tastic

Usage:
  crypto.py en FILE [-o FILE] [--dropbox]
  crypto.py de FILE [-o FILE] [--dropbox]
  crypto.py de [-o FILE] --dropbox
  crypto.py list
  crypto.py rm FILE
  crypto.py (-h | --help)
  crypto.py --version

Options:
  -o FILE       Specify output file [default: ./out.crypto]
  -h --help     Show this screen.
  --version     Show version.

'''
import sys, os, hashlib
import locale
from StringIO import StringIO
from docopt import docopt
from Crypto.Cipher import AES
from Crypto import Random
from getpass import getpass
from dropbox import client, rest

BS = AES.block_size
BIG_FILE_TRESHOLD = 400000

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

def DEBUG(msg):
    print msg

def fail(msg):
    LOG(msg, C.FAIL)
    sys.exit(1)

def fopen(name, perm):
    try:
        return open(name, perm)
    except IOError as e:
        fail('I/O error({0}): {1}'.format(e.errno, e.strerror))

pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

def hash(msg):
    return hashlib.new('ripemd160', msg).digest()

TOKEN_FILE = "token_store.txt"
token = 'RCzUIPNfK-0AAAAAAAAAASL3XaO6aQryvrJ9CECVHbN1d7E2lerM8sObRF8X5Dmm'
def uploadToDropbox(encrypted, fname, override=True):
    fsize = os.path.getsize(encrypted)
    fileHandle = open(encrypted, 'rb')
    api_client = client.DropboxClient(token)
    if (fsize > BIG_FILE_TRESHOLD):
        chunkedUploadDropbox(fileHandle, fname, fsize, api_client)
        return
    # token = open(TOKEN_FILE).read()
    LOG('Uploading to dropbox')
    response = api_client.put_file("/" + fname + ".crypto", fileHandle, override)
    DEBUG(response)

def size_fmt(num):
    for x in ['bytes','kB','MB','GB','TB']:
        if num < 1000:
            return "{0:3.1f}{1}".format(num, x)
        num /= 1000.0

def chunkedUploadDropbox(handle, fname, size, client):
    offset = 0
    retry_attempt = 0
    length = 100000
    uploader = client.get_chunked_uploader(handle, size)
    upload_id = None
    LOG('Uploading {0} in {1} chunks'.format(size_fmt(size), size_fmt(length)))
    while offset < size:
        try:
            chunk = min(length, size - offset)
            block = handle.read(chunk)
            offset, upload_id = client.upload_chunk(block, chunk, offset, upload_id)
            sys.stdout.write('{:.1%}\r'.format(offset / float(size)))
            sys.stdout.flush()
        except rest.ErrorResponse as e:
            print e
            retry_attempt += 1
            LOG('Error; retry #' + str(retry_attempt), C.WARN)
            pass
        except rest.RESTSocketError:
            fail('Could not connect to dropbox.com')
    uploader.upload_id = upload_id
    print uploader.finish('/' + fname + '.crypto')
    LOG('SUCCESS', C.OKG)

class DropboxHelper():
    def __init__(self):
        self.api_client = client.DropboxClient(token)

    def list(self):
        """list files in current remote directory"""
        resp = self.api_client.metadata('')

        if 'contents' in resp:
            for f in resp['contents']:
                name = f['path']
                if name[-7:] == '.crypto':
                    encoding = locale.getdefaultlocale()[1]
                    print "{0:<30} {1:<10} {2}"\
                        .format(name[1:-7], f['size'], f['modified'])

    def get(self, file_name):
        save_name = "." + file_name + ".tmp"
        try:
            f = self.api_client.get_file("/" + file_name + ".crypto")
        except rest.ErrorResponse as e:
            fail(str(e))
        handle = open(save_name, "wb")
        handle.write(f.read())
        handle.close()
        return save_name

    def remove(self, file_name):
        self.api_client.file_delete("/" + file_name + '.crypto')


class SecureUploader():
    def __init__(self, args):
        self.dropbox_mode = args['--dropbox']
        self.file_name = args['FILE']
        self.out_name = args['-o']
        if self.dropbox_mode or args['list'] or args['rm']:
            self.dropbox = DropboxHelper()
        if args['list']:
            self.dropbox.list()
            return
        if args['rm']:
            self.dropbox.remove(self.file_name)
            return
        if args['de'] and self.dropbox_mode:
            self.out_name = self.file_name
            LOG('Fetching file ' + self.file_name + ' from dropbox')
            self.file_name = self.dropbox.get(self.file_name)
            LOG('Fetching compleated', C.OKG)
        self.file = fopen(self.file_name, 'rb')
        pass1 = getpass('Enter your password: ')
        if args['en']:
            self.encrypt(pass1)
        elif args['de']:
            self.decrypt(pass1)

    def encrypt(self, pass1):
        size = os.path.getsize(self.file_name)
        pass2 = getpass('Confirm your password: ')
        if pass1 == pass2:
            key = pad(pass1)
        else:
            fail('Password does not match')
        LOG('ENCRYPTION...')
        message = b''
        iv = Random.new().read(BS)
        self.cipher = AES.new(key, AES.MODE_CBC, iv)
        checksum = hashlib.new('ripemd160', pass1)
        padding = False
        for piece in read_in_chunks(self.file, 16):
            checksum.update(piece)
            if (len(piece) < BS):
                piece = pad(piece)
                padding = True
            message += self.cipher.encrypt(piece)
        # if the file size was a multiple of 16 we need an extra step for padding
        if not(padding):
            piece = chr(BS) * BS
            message += self.cipher.encrypt(piece)
        outfile = fopen(self.out_name, 'wb')
        pack = checksum.digest() + hash(pass1) + iv + message
        outfile.write(pack)
        outfile.close()
        LOG('SUCCESS', C.OKG)
        if self.dropbox_mode:
            uploadToDropbox(self.out_name, self.file_name)
            os.remove(self.out_name)
            LOG('Uploaded to dropbox')
        else:
            LOG('Saved as: ' + self.out_name)

    def decrypt(self, pass1):
        data = self.file.read(BS+40)
        checksum = data[:20]
        h = data[20:40]
        iv = data[40:40+BS]
        # verify password
        if hash(pass1) == h:
            LOG('DECRYPTION...')
            key = pad(pass1)
            self.cipher = AES.new(key, AES.MODE_CBC, iv)
            message = b''
            for piece in read_in_chunks(self.file, 16):
                message += self.cipher.decrypt(piece)
            outfile = fopen(self.out_name, 'wb')
            secret = unpad(message)
            if hashlib.new('ripemd160', pass1 + secret).digest() != checksum:
                fail('File doesn\'t match')
            outfile.write(secret)
            LOG('SUCCESS', C.OKG)
            if self.dropbox_mode:
                os.remove(self.file_name)
            LOG('Saved as: ' + self.out_name)
        else:
            fail('Incorrect password.')

def main():
    args = docopt(__doc__, version='0.0.1')
    SecureUploader(args)

if __name__ == '__main__':
    main()