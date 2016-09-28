__author__ = 'pete'
from bitcoin import sha256
from bitcoin import random_key
from binascii import unhexlify

# creates merkle tree
# number of branches (n) up from base hash leaf constituents (l) to root is as follows:
# n=1 l(=1), n=2 l(>2<=4), n=3 l(>4<=8), n=4 l(>8<=16), n=5 l(>16<=32), n=6 l(>32<=64), n=7 l(<64>=128), n=8 l(>128<=256), n=9 l(>256<=512),

# creates lamport key pairs, signs and verifies a lamport one time signature.

def numlist(array):
    for a,b in enumerate(array):
        print a,b
    return

def sign_lkey(priv, message):       #perform lamport signature
    
    signature = [] 

    bin_lmsg = unhexlify(sha256(message))

    z = 0
    for x in range (0,32):
        l_byte = bin(ord(bin_lmsg[x]))[2:] #[2:][-1:]      #generate a binary string of 8 bits for each byte of 32/256.
        
        while len(l_byte) < 8:               #pad the zero's up to 8
                l_byte = '0'+ l_byte
        
        for y in range(0,8):
         if l_byte[-1:] == '0':
            signature.append(priv[z][0])
            l_byte = l_byte[:-1]
            z+=1
         else:
            signature.append(priv[z][1])
            l_byte = l_byte[:-1]
            z+=1

    return signature


def verify_lkey(signature, message, pub ):  #verify lamport signature

    bin_lmsg = unhexlify(sha256(message))

    verify = []

    z = 0

    for x in range (0,32):
        l_byte = bin(ord(bin_lmsg[x]))[2:]   #generate a binary string of 8 bits for each byte of 32/256.
        
        while len(l_byte) < 8:               #pad the zero's up to 8
                l_byte = '0'+ l_byte
        
        for y in range(0,8):
         if l_byte[-1:] == '0':
            verify.append((sha256(signature[z]),pub[z][0]))
            l_byte = l_byte[:-1]
            z+=1
         else:
            verify.append((sha256(signature[z]),pub[z][1]))
            l_byte = l_byte[:-1]
            z+=1

    for p in range(len(verify)):
        if verify[p][0] == verify[p][1]:
            pass
        else:
            return False    

    return True

def random_lkey():      #create random lamport signature scheme keypair

    priv = []
    pub = []

    for x in range (0,256):
        a,b = random_key(), random_key()
        priv.append((a,b))
        pub.append((sha256(a),sha256(b)))


    return priv, pub


def random_qkey():      #create random merkle tree signature keypair

    priv = []
    for x in range(0,8):
        priv.append(random_key())

    tree = Merkle()
    private_key = tree.create_tree(priv)
    pub_key = priv[len(private_key)]
    return pub_key, private_key

class Merkle():

 def create_tree(self,hash_array):
    self.merkle_base = []
    self.merkle_tree = []

    print 'parameters/private keys for hash layer:'

    for a, b in enumerate(hash_array):
        print (a,b)

    for hash in hash_array:
        self.merkle_base.append(hash)

    #print self.merkle_base

    num_hashes = len(self.merkle_base)

    if num_hashes <= 2:
        num_branches = 1
    elif num_hashes >2 and num_hashes <=4:
        num_branches = 2
    elif num_hashes >4 and num_hashes <=8:
        num_branches = 3
    elif num_hashes >8 and num_hashes <=16:
        num_branches = 4
    elif num_hashes >16 and num_hashes <=32:
        num_branches = 5
    elif num_hashes >32 and num_hashes <=64:
        num_branches = 6
    elif num_hashes >64 and num_hashes <=128:
        num_branches = 7
    elif num_hashes >128 and num_hashes <=256:
        num_branches = 8
    elif num_hashes >256 and num_hashes <=512:
        num_branches = 9


    print 'number of branches to root: ', num_branches

    self.merkle_tree.append(self.merkle_base)

    hashlayer = self.merkle_base

    for x in range(num_branches):       #iterate through each layer of the merkle tree starting with the base layer
        temp_array = []
        num_hashes = len(hashlayer)
        cycles = len(hashlayer)%2 + len(hashlayer)/2

        print 'branch cycle: ', str(x), ' - number of hashes / leaves:', num_hashes, ' - (pairs + modulo) per layer:', cycles

        y = 0

        for x in range(cycles):

            if y+1 == len(hashlayer):
             temp_array.append(str(hashlayer[y]))
            else:
             temp_array.append(sha256(str(hashlayer[y])+str(hashlayer[y+1])))
             y=y+2

        for a,b in enumerate(temp_array):
            print (a,b)

        self.merkle_tree.append(temp_array)
        hashlayer = temp_array

    print 'inverted merkle tree:'
    for a,b in enumerate(self.merkle_tree):
        print (a,b)
    return self.merkle_tree

 def check_item(self):
     return