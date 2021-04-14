#!/usr/bin/python3
import json
import time
import base64
from spqsigs import SigningKey
from spqsigs import Validator


print("Creating a new signing key. This may take a while.")
start = time.time()
sigkey = SigningKey(hashlen=24, wotsbits=12, merkledepth=10)
duration = time.time() - start
print("Creation took", duration, "seconds")
message = b"This is a message"
for _ in range(0,5):
    start = time.time()
    signature = sigkey.sign_message(message)
    duration = time.time() - start
    print("Signing took", duration, "seconds")
    validate = Validator(hashlen=24, wotsbits=12, merkledepth=10)
    ok, pubkey, index = validate(message, signature)
    print(ok, pubkey.hex().upper(), index)
print()
print("Restoring key from old state, this should go faster")
start = time.time()
serialized = json.dumps(sigkey.get_state())
sigkey2 = SigningKey(restore=sigkey.get_state())
duration = time.time() - start
print("Restoring took", duration, "seconds")
print()
for _ in range(0,5):
    start = time.time()
    signature = sigkey2.sign_message(message)
    duration = time.time() - start
    print("Signing took", duration, "seconds")
    ok, pubkey, index = validate(message, signature)
    print(ok, pubkey.hex().upper(), index)


