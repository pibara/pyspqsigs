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

def _deep_bytes_to_b64(obj):
    if isinstance(obj, dict):
        rval = dict()
        for key in obj:
            rval[key] = _deep_bytes_to_b64(obj[key])
        return rval
    if isinstance(obj, int):
        return obj
    if isinstance(obj, list):
        rval = list()
        for obj2 in obj:
            rval.append(_deep_bytes_to_b64(obj2))
        return rval
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode()
    return None

def _deep_b64_to_bytes(obj):
    if isinstance(obj, dict):
        rval = dict()
        for key in obj:
            rval[key] = _deep_b64_to_bytes(obj[key])
        return rval
    if isinstance(obj, int):
        return obj
    if isinstance(obj, list):
        rval = list()
        for obj2 in obj:
            rval.append(_deep_b64_to_bytes(obj2))
        return rval
    if isinstance(obj, str):
        return base64.b64decode(obj.encode())
    return None

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


def _pubkey_to_merkletree(key, hashfunction, salt, prefix=""):
    drval = dict()
    part1 = key[0]
    part2 = key[1]
    if len(key) > 2:
        breakpoint = int(len(key)/2)
        part1, dpart1 = _pubkey_to_merkletree(key[:breakpoint], hashfunction, salt, prefix + "0")
        part2, dpart2 = _pubkey_to_merkletree(key[breakpoint:], hashfunction, salt, prefix + "1")
        for key2 in dpart1:
            drval[key2] = dpart1[key2]
        for key3 in dpart2:
            drval[key3] = dpart2[key3]
    rval = hashfunction(part1 + part2, salt)
    if prefix:
        drval[prefix] = rval
        if len(key) == 2:
            drval[prefix + "0"] = part1
            drval[prefix + "1"] = part2
    return rval, drval


def _reconstruct_merkle_root(hashfunction, nodes, bitindex, reduced_pseudo_pubkey, salt):
    res = reduced_pseudo_pubkey
    # pylint: disable=consider-using-enumerate
    for index in range(0,len(bitindex)):
        if bitindex[index] == "0":
            res = hashfunction(res + nodes[index], salt)
        else:
            res = hashfunction(nodes[index] + res, salt)
    return res

def _onekey(onekey, hashfunction, wotsbits, salt, ndx):
    onekey_pub = list()
    for wotspair in onekey:
        public_wotspair = list()
        for subkey in wotspair:
            result = subkey
            for _ in range(0,int(math.pow(2, wotsbits))):
                result = hashfunction(result, salt)
            public_wotspair.append(result)
        onekey_pub.append(public_wotspair)
    return [onekey_pub, ndx]

def _key_from_seed(state, key_count, subkeys_per_key, hashfunction):
    rval = list()
    for index in range(0, key_count):
        onekey = list()
        for index2 in range(0, subkeys_per_key):
            wotspair = list()
            for direction in [b"L", b"R"]:
                unsalted = hashfunction(str(index).encode() +
                                        direction +
                                        str(index2).encode(),
                                        key=state["seed"])
                wotspair.append(hashfunction(unsalted,
                                             key=state["salt"]))
            onekey.append(wotspair)
        rval.append(onekey)
    return rval

def _digest_to_numlist(digest, state):
    digest_bits = list(BitArray(bytes=digest).bin)
    bitlists = list()
    while len(digest_bits) > state["wotsbits"]:
        bitlists.append(digest_bits[:state["wotsbits"]])
        digest_bits = digest_bits[state["wotsbits"]:]
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

def _create_signature_body(numlist, state, private_key, hashfunction):
    signature_body=list()
    # pylint: disable=consider-using-enumerate
    for index in range(0,len(numlist)):
        count1 = numlist[index]
        count2 = int(math.pow(2, state["wotsbits"])) - count1 - 1
        val1 = private_key[index][0]
        val2 = private_key[index][1]
        for _ in range (0, count1):
            val1 = hashfunction(val1, state["salt"])
        for _ in range (0, count2):
            val2 = hashfunction(val2, state["salt"])
        signature_body.append([val1,val2])
    return signature_body

def _create_signature_merkletree_header(state, merkletree):
    signature_header_mt = list()
    bitindex = BitArray("{0:#0{1}x}".format(state["next"],
                                            34)).bin[-state["merkledepth"]:]
    for index in range(0, state["merkledepth"]):
        prefix = bitindex[0:index]
        thisbit = bitindex[index]
        if thisbit == "1":
            signature_header_mt.append(merkletree[prefix + "0"])
        else:
            signature_header_mt.append(merkletree[prefix + "1"])
    return signature_header_mt

class SigningKey:
    """Class representing a hash based signing key"""
    # pylint: disable=too-many-arguments
    def __init__(self, wotsbits=12, merkledepth=10, hashlen=24, restore=None, multiproc=8):
        """Constructor should either be called in one of three ways:
        * Without any arguments. A new key is generated using the default settings.
        * With values set for wotsbits, merkledepth and hashlen. A new key is generated with
          these settings.
        * With a restore dict containing the old state of an existing statefull signing key.
        """
        if restore:
            self.state = _deep_b64_to_bytes(restore)
        else:
            self.state = dict()
            self.state["wotsbits"] = wotsbits
            self.state["merkledepth"] = merkledepth
            self.state["hashlen"] = hashlen
            self.state["next"] = 0
            self.state["seed"] = None
            self.state["salt"] = None
            self.state["pubkey"] = None
        self.hashfunction = _HashFunction(self.state["hashlen"])
        if self.state["seed"] is None:
            self.state["seed"] = self.hashfunction.generate_seed()
        if self.state["salt"] is None:
            self.state["salt"] = self.hashfunction.generate_salt()
        self.subkeys_per_key = math.ceil(self.hashfunction.bitcount/self.state["wotsbits"])
        self.key_count = int(math.pow(2,self.state["merkledepth"]))
        # (re)-generate secret key from seed.
        self.private_key = _key_from_seed(self.state,
                                          self.key_count,
                                          self.subkeys_per_key,
                                          self.hashfunction)
        # generate the big pubkey from private key (if not restorable)
        if self.state["pubkey"] is None:
            if multiproc > 1:
                r01 = len(self.private_key)
                self.state["pubkey"] = [None] * r01
                with concurrent.futures.ProcessPoolExecutor(max_workers = multiproc) as executor:
                    future_to_res = {executor.submit(_onekey,
                                                     self.private_key[ndx],
                                                     self.hashfunction,
                                                     self.state["wotsbits"],
                                                     self.state["salt"],
                                                     ndx): ndx for ndx in range(0,r01)}
                    for onekey in concurrent.futures.as_completed(future_to_res):
                        data = onekey.result()
                        self.state["pubkey"][data[1]] = data[0]
            else:
                self.state["pubkey"] = list()
                for onekey in self.private_key:
                    self.state["pubkey"].append(_onekey(onekey,
                                                        self.hashfunction,
                                                        self.state["wotsbits"],
                                                        self.state["salt"],0)[0])
        # reduce the public key size
        medium_public_key = list()
        for big_pubkey in self.state["pubkey"]:
            pkey, _ = _pubkey_to_merkletree(_flatten_pubkey(big_pubkey), self.hashfunction,
                                           self.state["salt"])
            medium_public_key.append(pkey)
        # Turn remaining pubkey into a merkle tree and root
        self.public_key, self.merkletree = _pubkey_to_merkletree(medium_public_key,
                                                                self.hashfunction,
                                                                self.state["salt"])
    def sign_digest(self, digest):
        """Sign a message digest."""
        if self.state["next"] >= self.key_count:
            raise RuntimeError("Private key has been exhausted")
        # Get the current private key
        private_key = self.private_key[self.state["next"]]
        # Convert the digest to a list of integers for signing.
        numlist = _digest_to_numlist(digest, self.state)
        # Create the signature body
        signature_body = _create_signature_body(numlist, self.state, private_key,
                                                self.hashfunction)
        # Create the merkletree signature header
        signature_header_mt = _create_signature_merkletree_header(self.state, self.merkletree)
        # encode the key index
        bindex = struct.pack(">H",self.state["next"])
        # Compose the signature from:
        # * pubkey
        # * key-index
        # * merkle-tree header
        # * wots signatures
        signature = b""
        signature += self.public_key
        signature += self.state["salt"]
        signature += bindex
        for mtnode in signature_header_mt:
            signature += mtnode
        for wotspair in signature_body:
            for wotsval in wotspair:
                signature += wotsval
        self.state["next"] += 1
        return signature
    def sign_message(self, message):
        """Sign a message"""
        msg_digest = self.hashfunction(message, self.state["salt"])
        return self.sign_digest(msg_digest)
    def get_state(self):
        """Get serializable signing key state"""
        return _deep_bytes_to_b64(self.state)


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
        msg_digest = self.hashfunction(message,salt)
        # Convert the digest to a list of integers for signing.
        digest_bits = list(BitArray(bytes=msg_digest).bin)
        bitlists = list()
        while len(digest_bits) > self.wotsbits:
            bitlists.append(digest_bits[:self.wotsbits])
            digest_bits = digest_bits[self.wotsbits:]
        bitlists.append(digest_bits)
        numlist = list()
        for bits in bitlists:
            num = 0
            for bit in bits:
                num *= 2
                if bit == "1":
                    num += 1
            numlist.append(num)
        sigindex = struct.unpack(">H",signature[2*hlenb:2*hlenb+2])[0]
        sigindex_bits = BitArray("{0:#0{1}x}".format(sigindex,34)).bin[-self.merkledepth:]
        merkle_header = signature[2*hlenb+2:2*hlenb+2+self.merkledepth*hlenb]
        merkle_header = [merkle_header[i:i+hlenb] for i in range(0, len(merkle_header), hlenb)]
        signature_body = signature[2*hlenb+2+self.merkledepth*hlenb:]
        signature_body = [signature_body[i:i+hlenb] for i in range(0, len(signature_body), hlenb)]
        signature_body = [signature_body[i:i+2] for i in range(0, len(signature_body), 2)]
        # Complete the double WOTS chain.
        big_pubkey = list()
        # pylint: disable=consider-using-enumerate
        for index in range(0, len(numlist)):
            count1 = int(math.pow(2,self.wotsbits)) - numlist[index]
            count2 = numlist[index] + 1
            val1 = signature_body[index][0]
            val2 = signature_body[index][1]
            for _ in range (0, count1):
                val1 = self.hashfunction(val1, salt)
            for _ in range (0, count2):
                val2 = self.hashfunction(val2, salt)
            big_pubkey.append([val1, val2])
        # Reduce the wots values to a single hash
        pkey, _ = _pubkey_to_merkletree(_flatten_pubkey(big_pubkey), self.hashfunction, salt)
        # Check the single hash with the merkle tree header.
        mt_root_candidate = _reconstruct_merkle_root(
            self.hashfunction,
            list(reversed(merkle_header)),
            list(reversed(list(sigindex_bits))),
            pkey,
            salt)
        return pubkey == mt_root_candidate, pubkey, sigindex
