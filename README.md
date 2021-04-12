# pyspqsigs
Python Simple (Hash Based) Post Quantum Signatures

This library is currently a work in progress. It is meant to become part of a collection of libraries for aiding the HIVE blockchain ecosystem towards a post-quantum future.

Check out the following two blog posts for a basic idea of what this library aims to implement.

* [part 1](https://hive.blog/hive-161707/@pibara/a-practical-introduction-into-hash-based-signatures-using-python-part-one)
* [part 2](https://hive.blog/hive-161707/@pibara/a-practical-introduction-into-hash-based-signatures-using-python-part-two)

The code in this library is based mostly on the sample code from the blog posts.

![image](https://user-images.githubusercontent.com/289546/114308898-ab79b300-9ae5-11eb-99bb-c4603b1a07f3.png)


Some aditions:

* Use of a per private key salt used in most hashing operations
* Standirisation on the use of BLAKE2
* State serialization and deserialization into a JSON compatible structure.
* Use of multiprocessing for faster signing key generation

## status

* We should get a second pair of eyes to look at the code.

## install

You can install (the currently experimental version of) spqsigs using the following command:

```
python3 -m pip install spqsigs
```

## usage

### signing

To use the signing part of spqsigs, import the SigningKey class and instantiate it.
The constructor allows you to specify:

* hashlen: The number of bytes to use as digest length dor BLAKE2b. This defaults to 24 bytes.
* wotsbits: The number of bits to sign with one set of WOTS chains. Note that each bit makes signing key generation a factor of two slower. This value defaults to 12 bit.
* merkledepth: The depth (or height) of the top level merkle tree. You can sign two to the power depth messages with a single signing key before it depletes. Adding one level to the depth doubles both the number of messages you can sign with a single key and the amount of time to generate a signing key.
* multiproc: The number of rocesses to use during signing key generation. This defaults to 8.
            
```python
from spqsigs import SigningKey

sigkey = SigningKey(hashlen=24, wotsbits=12, merkledepth=10, multiproc=4)
```

Once the signing key is constructed, you can use it to sign messages with untill the key depletes.

```python
message = b"This is a message"
signature = sigkey.sign_message(message)
```

### state

It is important to realizer that hash-based signing keys are statefull. After creation, but also after each signature made, the state of the signing key should be saved to persistent storage. 

While important, the spqsigs library has no support for encrypting this storage with a passphrase. You should implement something for that yourself when using this library.

The below serialization to unencrypted JSON is usefull for experiments: 

```python
import json

with open("signkey_state.json", "w") as outfil:
    json.dump(sigkey.get_state(), outfile)
```

We can restore the signing key by using the restore constructor argument.
```python
with open("signkey_state.json") as infil:
    oldstate = json.load(infil)
sigkey = SigningKey(restore=oldstate)
````

### validation

For validating signatures, we impor tand instantiate the validator Class.
Make sure to use the exact same parameters for hashlen, wotsbits and merkledepth as used for the 
construction of the SigningKey object.

```python
from spqsigs import Validator

validate = Validator(hashlen=24, wotsbits=12, merkledepth=10)
```

Now we can invoke the validator with the message and the signature. This invocation returns three values. If validation was succesfull or not, the pubkey of the signer, and the index of the signature.

```python
ok, pubkey, index = validate(message, signature)
```

It is adviced to not accept the same index from the same public key twice.

## Signature format:

A spqsigs signature has the following structure:

* public key: haslen bytes
* salt : hashlen bytes
* index : 2 bytes
* merkle tree header: merkledepth minus one times hashlen
* wots body: two times hashlen times the ceiling of hashlen divided by wotsbits

Please note that spqsigs signatures are considerably larger than what you might be used to when using ECDSA signatures. 
