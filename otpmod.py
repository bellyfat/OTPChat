import _pickle as cPickle
import string
import secrets
import multiprocessing as multi

class OTP():
    defaults_alphabet = string.digits+string.ascii_letters+string.punctuation+" "
    defaults_message_length = 64
    defaults_key_number = 0xffff
    defaults_file = "key.dict"
    
    def __init__(self, alphabet=string.digits+string.ascii_letters+string.punctuation+" ", message_length=64, key_number=0xffff, file="key.dict", outqueue=None):
        self.a = self.defaults_alphabet#alphabet
        self.n = message_length
        self.MAX_KEYS = key_number
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
    print(multi.cpu_count())
