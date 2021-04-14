"""Python module for Simple Post Quantum Signatures

This module provides simple BLAKE2 hash-based based signature using a simple
design made out of a combination of a merkle tree and dual WOTS chains.


"""
import math
import os
import struct
import base64
from hashlib import blake2b
import concurrent.futures
from bitstring import BitArray


class _HashFunction:
    def __init__(self, length):
        self.bitcount = length * 8
        self.hashlength = length

    def __call__(self, data, key=b""):
        """Call the actual hash function"""
        return blake2b(data, digest_size=self.hashlength, key=key).digest()

    def generate_seed(self):
        """Generate a random seed with same length as our hash function result"""
        return os.urandom(self.hashlength)

    def generate_salt(self):
        """Generate a random salt with same length as our hash function result"""
        return self.generate_seed()


def _flatten_pubkey(key):
    rval = list()
    for subkey in key:
        rval.append(subkey[0])
        rval.append(subkey[1])
    return rval


def _pubkey_to_merkletree(key, hashfunction, salt, prefix="", mtdict=False):
    if mtdict:
        drval = dict()
    part1 = key[0]
    part2 = key[1]
    if len(key) > 2:
        breakpoint = int(len(key)/2)
        if mtdict:
            part1, dpart1 = _pubkey_to_merkletree(key[:breakpoint], hashfunction, salt, 
                                                  prefix + "0", mtdict)
            part2, dpart2 = _pubkey_to_merkletree(key[breakpoint:], hashfunction, salt, 
                                                  prefix + "1", mtdict)
            for key2 in dpart1:
                drval[key2] = dpart1[key2]
            for key3 in dpart2:
                drval[key3] = dpart2[key3]
        else:
            part1 = _pubkey_to_merkletree(key[:breakpoint], hashfunction, salt, 
                                          prefix + "0", mtdict)
            part2 = _pubkey_to_merkletree(key[breakpoint:], hashfunction, salt, 
                                          prefix + "1", mtdict)
    rval = hashfunction(part1 + part2, salt)
    if mtdict:
        if prefix:
            drval[prefix] = rval
            if len(key) == 2:
                drval[prefix + "0"] = part1
                drval[prefix + "1"] = part2
        return rval, drval
    else:
        return rval


def _reconstruct_merkle_root(hashfunction, nodes, bitindex, reduced_pseudo_pubkey, salt):
    res = reduced_pseudo_pubkey
    # pylint: disable=consider-using-enumerate
    for index in range(0, len(bitindex)):
        if bitindex[index] == "0":
            res = hashfunction(res + nodes[index], salt)
        else:
            res = hashfunction(nodes[index] + res, salt)
    return res


def _digest_to_numlist(digest, wotsbits):
    digest_bits = list(BitArray(bytes=digest).bin)
    bitlists = list()
    while len(digest_bits) > wotsbits:
        bitlists.append(digest_bits[:wotsbits])
        digest_bits = digest_bits[wotsbits:]
    bitlists.append(digest_bits)
    numlist = list()
    for bits in bitlists:
        num = 0
        for bit in bits:
            num *= 2
            if bit == "1":
                num += 1
        numlist.append(num)
    return numlist


def _complete_wots_chain(numlist, wotsbits, signature_body, salt, hashfunction):
    big_pubkey = list()
    # pylint: disable=consider-using-enumerate
    for index in range(0, len(numlist)):
        count1 = int(math.pow(2, wotsbits)) - numlist[index]
        count2 = numlist[index] + 1
        val1 = signature_body[index][0]
        val2 = signature_body[index][1]
        for _ in range(0, count1):
            val1 = hashfunction(val1, salt)
        for _ in range(0, count2):
            val2 = hashfunction(val2, salt)
        big_pubkey.append([val1, val2])
    return big_pubkey

class SubKey:
    def __init__(self, seed, salt, index, subindex, wotsbits, hashfunction):
        self.salt = salt
        self.wotsbits = wotsbits
        self.chainlen = int(math.pow(2, wotsbits))
        self.hashfunction = hashfunction
        self.privkeys = list()
        self.public_key = None
        for direction in [b"L", b"R"]:
            designator = str(index).encode() + direction + str(subindex).encode()
            unsalted = hashfunction(designator, seed)
            self.privkeys.append(hashfunction(unsalted,salt))

    def pubkey(self):
        if self.public_key is None:
            pubkeys = list()
            for subkey in self.privkeys:
                result = subkey
                for _ in range(0, self.chainlen):
                    result = self.hashfunction(result, self.salt)
                pubkeys.append(result)
            self.public_key = self.hashfunction(pubkeys[0] + pubkeys[1], self.salt) 
        return self.public_key

    def __getitem__(self, index):
        count1 = index
        count2 = self.chainlen - count1 - 1
        val1 = self.privkeys[0]
        val2 = self.privkeys[1]
        for _ in range(0, count1):
            val1 = self.hashfunction(val1, self.salt)
        for _ in range(0, count2):
            val2 = self.hashfunction(val2, self.salt)
        return val1 + val2

def mt_reduce(keys, hashfunction, salt):
    count = len(keys)
    if count > 2:
        half = int(count/2)
        reduced1 = mt_reduce(keys[:half], hashfunction, salt)
        reduced2 = mt_reduce(keys[half:], hashfunction, salt)
        return hashfunction(reduced1 + reduced2, salt)
    else:
        return hashfunction(keys[0] + keys[1], salt)
       

def digest_to_numlist(digest, wotsbits):
    digest_bits = list(BitArray(bytes=digest).bin)
    bitlists = list()
    while len(digest_bits) > wotsbits:
        bitlists.append(digest_bits[:wotsbits])
        digest_bits = digest_bits[wotsbits:]
    bitlists.append(digest_bits)
    numlist = list()
    for bits in bitlists:
        num = 0
        for bit in bits:
            num *= 2
            if bit == "1":
                num += 1
        numlist.append(num)
    return numlist

class PrivateKey:
    def __init__(self, seed, salt, index, subkeys, wotsbits, hashfunction):
        self.salt = salt
        self.hashfunction = hashfunction
        self.wotsbits = wotsbits
        self.subkeys = list()
        self.index = index
        for subindex in range(0, subkeys):
            self.subkeys.append(SubKey(seed, salt, index, subindex, wotsbits, hashfunction))
    
    def pubkey(self):
        pubkeys = list()
        for subkey in self.subkeys:
            pubkey = subkey.pubkey()
            pubkeys.append(pubkey)
        return mt_reduce(pubkeys, self.hashfunction, self.salt)

    def  __getitem__(self, msg_digest):
        numlist = digest_to_numlist(msg_digest, self.wotsbits)
        rval = b""
        for index in range(0, len(numlist)):
            rval += self.subkeys[index][numlist[index]]
        return rval

class PrivateKeys:
    def __init__(self, seed, salt, size, wotsbits, hashfunction, multiproc):
        self.seed = seed
        self.salt = salt
        self.size = size
        self.wotsbits = wotsbits
        self.hashfunction = hashfunction
        self.multiproc = multiproc
        self.keys = dict()
        self.pub_keys = None
        self.subkey_count =  math.ceil(hashfunction.bitcount/wotsbits)

    def __getitem__(self, index):
        if isinstance(index, int):
            if index < 0 or index >= self.size:
                raise IndexError("Index out of range")
            if index not in self.keys:
                self.keys[index] = PrivateKey(self.seed, self.salt, 
                                              index,
                                              self.subkey_count,
                                              self.wotsbits,
                                              self.hashfunction)
            return self.keys[index]
        else:
            raise RuntimeError("Index should be an integer")

    def _future_helper(self, index):
        obj =  self[index]
        pk = obj.pubkey()
        return pk, index

    def pubkey(self):
        rval = [None] * self.size
        with concurrent.futures.ProcessPoolExecutor(max_workers=self.multiproc) as executor:
            future_to_res = {executor.submit(self._future_helper,
                                             ndx): ndx for ndx in range(0, self.size)}
            for onekey in concurrent.futures.as_completed(future_to_res):
                data = onekey.result()
                rval[data[1]] = data[0]
        return rval


def pubkey_to_merkletree(key, hashfunction, salt, prefix=""):
    drval = dict()
    part1 = key[0]
    part2 = key[1]
    if len(key) > 2:
        breakpoint = int(len(key)/2)
        part1, dpart1 = pubkey_to_merkletree(key[:breakpoint], hashfunction, salt,
                                              prefix + "0")
        part2, dpart2 = pubkey_to_merkletree(key[breakpoint:], hashfunction, salt,
                                              prefix + "1")
        for key2 in dpart1:
            drval[key2] = dpart1[key2]
        for key3 in dpart2:
            drval[key3] = dpart2[key3]
    rval = hashfunction(part1 + part2, salt)
    drval[prefix] = rval
    if len(key) == 2:
        drval[prefix + "0"] = part1
        drval[prefix + "1"] = part2
    if prefix:
        return rval, drval
    return drval


class MerkleTree:
    def __init__(self, privkey, hashfunction, salt, mtdepth, restore):
        self.mtdepth = mtdepth
        if restore:
            self.mtree_lookup = dict()
            for key in restore:
                self.mtree_lookup[key] = base64.b64decode(restore[key].encode())
        else:
            self.mtree_lookup = pubkey_to_merkletree(privkey.pubkey(),
                                                  hashfunction,
                                                  salt)
    def pubkey(self):
        return self.mtree_lookup[""]

    def __getitem__(self, index):
        rval = b""
        index_bits = BitArray("{0:#0{1}x}".format(index, 34)).bin[-self.mtdepth:]
        for bindex in range(0, self.mtdepth):

            prefix = index_bits[0:bindex]
            thisbit = index_bits[bindex]
            if thisbit == "1":
                rval += self.mtree_lookup[prefix + "0"]
            else:
                rval += self.mtree_lookup[prefix + "1"]
        return rval

    def get_state(self):
        rval = dict()
        for key in self.mtree_lookup:
            rval[key] = base64.b64encode(self.mtree_lookup[key]).decode() 
        return rval

class SigningKey:
    def __init__(self, wotsbits=12, merkledepth=10, hashlen=24, restore=None, multiproc=8):
        mtrestore = None
        self.next_index = 0
        self.seed = None
        self.salt = None
        self.wotsbits = wotsbits
        self.merkledepth = merkledepth
        self.hashlen = hashlen
        if restore:
            if "wotsbits" in restore:
                self.wotsbits = restore["wotsbits"]
            if "merkledept" in restore:
                self.erkledepth = restore["merkledepth"]
            if "hashlen" in restore:
                self.hashlen = restore["hashlen"]
            if "next_index" in restore:
                self.next_index = restore["next_index"]
            if "seed" in  restore:
                self.seed = base64.b64decode(restore["seed"].encode())
            if "salt" in  restore:
                self.seed = base64.b64decode(restore["salt"].encode())
            if "merkletree" in restore:
                mtrestore = restore["merkletree"]
        self.hashfunction = _HashFunction(hashlen)
        if self.seed is None:
            self.seed = self.hashfunction.generate_seed()
        if self.salt is None:
            self.salt = self.hashfunction.generate_salt()
        size = int(math.pow(2, self.merkledepth)) 
        self.private_keys = PrivateKeys(self.seed,
                                        self.salt,
                                        size,
                                        self.wotsbits,
                                        self.hashfunction,
                                        multiproc)
        self.merkletree = MerkleTree(self.private_keys,
                                     self.hashfunction,
                                     self.salt,
                                     self.merkledepth,
                                     mtrestore)

    def sign_digest(self, digest):
        bindex = struct.pack(">H", self.next_index)
        rval = self.merkletree.pubkey() + self.salt + bindex + self.merkletree[self.next_index]
        rval += self.private_keys[self.next_index][digest]
        self.next_index +=1
        return rval

    def sign_message(self, message):
        """Sign a message"""
        msg_digest = self.hashfunction(message, self.salt)
        return self.sign_digest(msg_digest)

    def get_state(self):
        rval = dict()
        rval["seed"] = base64.b64encode(self.seed).decode()
        rval["salt"] = base64.b64encode(self.salt).decode()
        rval["next_index"] = self.next_index
        rval["wotsbits"] = self.wotsbits
        rval["merkledepth"] = self.merkledepth
        rval["hashlength"] = self.hashlen
        rval["merkletree"] = self.merkletree.get_state()
        return rval


class Validator:
    """Validator for signatures created with a same settings SigningKey"""
    # pylint: disable=too-few-public-methods
    def __init__(self, hashlen=24, wotsbits=12, merkledepth=10):
        """Constructor"""
        self.hashfunction = _HashFunction(hashlen)
        self.wotsbits = wotsbits
        self.merkledepth = merkledepth

    def __call__(self, message, signature):
        """Validate message signature"""
        hlenb = int(self.hashfunction.bitcount/8)
        pubkey = signature[:hlenb]
        salt = signature[hlenb:2*hlenb]
        # Convert the digest to a list of integers for signing.
        numlist = _digest_to_numlist(self.hashfunction(message, salt), self.wotsbits)
        sigindex = struct.unpack(">H", signature[2*hlenb:2*hlenb+2])[0]
        sigindex_bits = BitArray("{0:#0{1}x}".format(sigindex, 34)).bin[-self.merkledepth:]
        merkle_header = signature[2*hlenb+2:2*hlenb+2+self.merkledepth*hlenb]
        merkle_header = [merkle_header[i:i+hlenb] for i in range(0, len(merkle_header), hlenb)]
        signature_body = signature[2*hlenb+2+self.merkledepth*hlenb:]
        signature_body = [signature_body[i:i+hlenb] for i in range(0, len(signature_body), hlenb)]
        signature_body = [signature_body[i:i+2] for i in range(0, len(signature_body), 2)]
        # Complete the double WOTS chain.
        big_pubkey = _complete_wots_chain(numlist, self.wotsbits, signature_body, salt,
                                          self.hashfunction)
        # Reduce the wots values to a single hash
        pkey = _pubkey_to_merkletree(_flatten_pubkey(big_pubkey), self.hashfunction, salt)
        # Check the single hash with the merkle tree header.
        mt_root_candidate = _reconstruct_merkle_root(
            self.hashfunction,
            list(reversed(merkle_header)),
            list(reversed(list(sigindex_bits))),
            pkey,
            salt)
        return pubkey == mt_root_candidate, pubkey, sigindex
