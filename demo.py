#!/usr/bin/python3
import json
import time
import base64
from spqsigs import SigningKey, Validator


print("Creating a new signing key. This may take a while.")
start = time.time()
sigkey = SigningKey(hashlen=2, wotsbits=4, merkledepth=5)
duration = time.time() - start
print("That took", duration, "seconds")
print("Restoring key from old state, this should go faster")
start = time.time()
serialized = json.dumps(sigkey.get_state())
sigkey2 = SigningKey(restore=sigkey.get_state())
duration = time.time() - start
print("That took", duration, "seconds")
print()
message = b"This is a message"
signature = sigkey.sign_message(message)
print(signature.hex().upper())
print()
validate = Validator(hashlen=2, wotsbits=4, merkledepth=5)
ok, pubkey, index = validate(message, signature)
print(ok, pubkey.hex().upper(), index)


