# Note: Big refactoring pending

The pyspqsigs project is currently undergoing a bit refactoring into what has been renamed to [coinZdense](https://coin.z-den.se/). Check out the [technical deep-dive](https://hive.blog/coinzdense/@pibara/coinzdense-deep-dive-index) documents to see what's comming. The The part of the project is currently being continued with a fresh code-base [here](https://github.com/pibara/coinzdense-python).

# pyspqsigs
Python Simple (Hash Based) Post Quantum Signatures

# Update comming

Please note that this repo currently contains a proof-of-concept version of the project. I am currently working on a  Minimal Viable Product for the project in the [C++ version of spq-sigs](https://github.com/pibara/spq-sigs). When the MVP is up and running in C++, this Python repo will be ported to work the same as the C++ version of the project.

The below documentation is for the current proof of concept code in the repository.

# The Proof-Of-Concept code

This library is currently in Proof-Of-Concept status. It is currently being reimplemented and refactored into a more extensive C++ version of this library that will later get backported to this Python library again. The aim is to eventualy make a version in many languages, implementing multi-tree hash-based signatures, and a simple wallet for password protected keys and signing state. 

* **Python** (this library, currently Proof-Of-Concept)
* [C++](https://github.com/pibara/spq-sigs) (Redesign of this library in C++ with extra features)

When these two libraries are done and made 100% compatible, the following languages are candidates to implement next in order of my current personal preference:

* **Rust** : Given that the full design is now being done in C++, folowed by Python, Rust is technologically the most obvious choiche for a next port.
* **JavaScript** : This project started meant for HIVE. While it is no longer a HIVE exclusive project, HIVE, as a blockchain that reuses signing key by design remains one of the chains most in need of hash based signatures for its entire ecosystem. Without JavaSript right now, it won't be a match. So after Rust, I'll work on the JavsScript port.
* **Clojure** : I've been using the amazing block-chain based database FlureeDB at work for a while now. Like HIVE, FlureeDB relies on ECDSA key-reusage by design. My clojure and lisp skills are pretty minimal right now, but I feel that porting to Clojure could be an amazing learning experience for me in that. If I succeed, maybe the Clojure port could one day be used from a FlureeDB fork.  
* **Elixir** : Elixir is just an amazing language that I've played around with a bit, but that I haven't done as much with as I would have liked to. So basically this port will be an excuse for me to work with Elixir a bit more, and an excuse to delay working on the Ruby and PhP ports.
* **Monte**

Check out the following two blog posts for a basic idea of what this library aims to implement. Note thet in the C++ code, changes, mostly simplifications, have been made to the design not mentioned in these posts.

* [part 1](https://hive.blog/hive-161707/@pibara/a-practical-introduction-into-hash-based-signatures-using-python-part-one)
* [part 2](https://hive.blog/hive-161707/@pibara/a-practical-introduction-into-hash-based-signatures-using-python-part-two)

The code in the P.O.C version of this  library is based mostly on the sample code from the blog posts.

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

* public key: haslen bytes (the green dot in the diagram)
* salt : hashlen bytes (see below)
* index : 2 bytes (the grey-dot number two in the diagram)
* merkle tree header: merkledepth minus one times hashlen (the red dots in the diagram)
* wots body: two times hashlen times the ceiling of hashlen divided by wotsbits (the orange dots in the diagram)

Please note that spqsigs signatures are considerably larger than what you might be used to when using ECDSA signatures. 

## What's up with the salt?

In order to prevent rainbow table like attacks where an attacker could try to basically mine seeds, we added a salt to the entire collection of trees and chains. Doing so means that each public key would need to be targeted individually, and no rainbow table work could be done. The salt is a random number with the same length as the digest length primitive used in BLAKE2b operations, and is bound to a spqsigs keypair for the lifetime of the key.
