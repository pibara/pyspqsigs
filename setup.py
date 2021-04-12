from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

setup(
    name='spqsigs',
    version='0.1.1',
    description='Simple Post-Quantum Signature library',
    long_description="""Library for hash-based signatures using BLAKE2, salt,
    double WOTS chains, and Merkle-trees.
    """,
    url='https://github.com/pibara/pyspqsigs',
    author='Rob J Meijer',
    author_email='pibara@gmail.com',
    license='BSD',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Operating System :: OS Independent',
        'Environment :: Other Environment'
    ],
    keywords='signing postquantum blake2 merkletree wots',
    install_requires=["bitstring"],
    packages=find_packages(),
)


