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

## status

* Multiprocessing for key creation not yet working. Needed for speeding up slow key creation.
* The linters are not yet happy with the code, will fix this once signing and validation match up again
* Need to add a setup.py, and need to push to pypi once stuf works and is stable.
* We should get a second pair of eyes to look at the code.
