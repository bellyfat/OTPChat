import _pickle as cPickle
import string
import secrets
import hashlib
import tempfile
import os
#import multiprocessing as multi

class OTP():
    defaults_alphabet = string.digits+string.ascii_letters+string.punctuation+" "
    defaults_message_length = 64
    defaults_key_number = 0xffff
    defaults_file = "key.dict"
    
    def __init__(self, alphabet=string.digits+string.ascii_letters+string.punctuation+" ", message_length=64, key_number=0xffff, file="key.dict", outqueue=None):
        self.a = self.defaults_alphabet#alphabet
        self.n = message_length
        self.MAX_KEYS = key_number
        if key_number < 255:
            self.MAX_KEYS = 255
        self.file = file
        if not outqueue == None:
            outqueue.put("Starting")
        self.secure_random = secrets.SystemRandom()
        try:
            with open(self.file,'rb') as f:
                self.key_dict = cPickle.load(f)
                print("Taking dictionary settings from file")
                settings = self.key_dict[0]
                self.a = settings[0]
                self.n = settings[1]
                self.MAX_KEYS = settings[2]
        except FileNotFoundError:
            self.key_gen(outqueue)
        print("keys remaining: {}".format(len(self.key_dict)-1))
        if not outqueue == None:
            outqueue.put("Stopped")
        self.checksum = ""

    def check_dict_for_changes(self):
        BLOCKSIZE = 1088
        m = hashlib.sha3_256()
        with open(self.file, "rb") as f:
            buf = f.read(BLOCKSIZE)
            m.update(buf)
            while len(buf) > 0:
                buf = f.read(BLOCKSIZE)
                m.update(buf)
        tmpfile = "{}\\{}".format(tempfile.gettempdir(),self.file)
        tmphash = ""
        if os.path.isfile(tmpfile):
            with open(tmpfile, "rb") as f:
                tmphash = f.read(256).hex()
        else:
            print("warning: No record of key dictionary, creating hash")
            with open(tmpfile, "wb") as f:
                f.write(m.digest())
        if m.hexdigest() == tmphash:
            print("key dictionary matches hash")
        else:
            print("warning: key dictionary does not match hash")
            print("warning: it may be new or edited")

    def get_my_checksum(self, NICK):
        BLOCKSIZE = 1088
        m = hashlib.sha3_256()
        with open(self.file, "rb") as f:
            buf = f.read(BLOCKSIZE)
            m.update(buf)
            while len(buf) > 0:
                buf = f.read(BLOCKSIZE)
                m.update(buf)
        m.update("{}".format(NICK).encode())
        self.checksum = m.hexdigest()
        return(self.checksum)

    def verify_peer_checksum(self, PEER, peer_checksum):
        BLOCKSIZE = 1088
        m = hashlib.sha3_256()
        with open(self.file, "rb") as f:
            buf = f.read(BLOCKSIZE)
            m.update(buf)
            while len(buf) > 0:
                buf = f.read(BLOCKSIZE)
                m.update(buf)
        m.update("{}".format(PEER).encode())
        checksum = m.hexdigest()
        print(checksum)
        print(peer_checksum)
        return(True if checksum == peer_checksum else False)
    
    def key_gen(self, outqueue):
        print("Generating new key dictionary with {} keys".format(self.MAX_KEYS))
        print("This may take a few minutes")
        keys = {}
        last_prog = 0
        keys[0] = (self.a, self.n, self.MAX_KEYS)
        for i in range(self.MAX_KEYS):
            keys[i+1] = "".join(self.secure_random.choice(self.a) for i in range(self.n))
            if i%int(self.MAX_KEYS/100) == 0:
                prog = int(i/(self.MAX_KEYS/100))
                if not prog == last_prog and not outqueue == None:
                    outqueue.put("Step")
                    last_prog = prog
        with open(self.file,'wb') as f:
            cPickle.dump(keys, f, -1)
        self.key_dict = keys
        print("Finished")

    def get_key_len(self, x):
        return(len(hex(x))-2)

    def encode(self,m):
        try:
            keyprefix = self.get_key_len(self.MAX_KEYS)
            prefix, k = self.secure_random.choice(list(self.key_dict.items())[1:])
            self.key_dict.pop(prefix)
            with open(self.file,'wb') as f:
                cPickle.dump(self.key_dict, f, -1)
            prefix = "{0:0{1}x}".format(prefix,keyprefix)
            m = m.ljust(self.n)
            if len(m)>self.n:
                raise ValueError("message length greater than {}".format(self.n))
            message = prefix+''.join(self.a[(self.a.index(m[i])+self.a.index(k[i]))%len(self.a)] for i in range(self.n))
            return(message, True)
        except KeyError as err:
            return("Unable to encode message: {}".format(err), False)
        except ValueError as err:
            return("Unable to encode message: {}".format(err), False)

    def decode(self,d):
        keyprefix = self.get_key_len(self.MAX_KEYS)
        try:
            k = self.key_dict[int(d[:keyprefix],16)]
            self.key_dict.pop(int(d[:keyprefix],16))
            with open(self.file,'wb') as f:
                cPickle.dump(self.key_dict, f, -1)
            d = d[keyprefix:]
            return(''.join(self.a[(self.a.index(d[i])-self.a.index(k[i]))%len(self.a)] for i in range(self.n)))
        except KeyError:
            return("Unable to decode data")

if __name__ == '__main__':
    otp = OTP()
    x = otp.encode("hi")
    print(x)
    print(otp.verify_dict_using_nick("test"))
