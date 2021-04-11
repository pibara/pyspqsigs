# pyspqsigs
Python Simple (Hash Based) Post Quantum Signatures

This library is currently a work in progress. It is meant to become part of a collection of libraries for aiding the HIVE blockchain ecosystem towards a post-quantum future.

Check out the following two blog posts for a basic idea of what this library aims to implement.

* [part 1](https://hive.blog/hive-161707/@pibara/a-practical-introduction-into-hash-based-signatures-using-python-part-one)
* [part 2](https://hive.blog/hive-161707/@pibara/a-practical-introduction-into-hash-based-signatures-using-python-part-two)

The code in this library is based mostly on the sample code from the blog posts.

Some aditions:

* Use of a per private key salt used in most hashing operations
* Standirisation on the use of BLAKE2
* State serialization and deserialization into a JSON compatible structure.

## status

* Currently the introduction of salting has broken the code. Will look into this soon.
* The linters are not yet happy with the code, will fix this once signing and validation match up again
* There is a lot of room for paralelization in new key generation. Need to look into this before declaring lib production ready.
* Need to add a setup.py, and need to push to pypi once stuf works and is stable.
* We should get a second pair of eyes to look at the code.
