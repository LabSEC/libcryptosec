Libcryptosec
===========
Object Oriented Wrapper for the OpenSSL libcrypto library. 

[![Build Status](https://travis-ci.org/LabSEC/libcryptosec.svg?branch=master)](https://travis-ci.org/LabSEC/libcryptosec)

## Contributions

* We take in pull requests, feel free to fork :-)
* the Master and Dev branches are protected. Use branches and 
pull requests.
* Avoid creating backwards compability! We use this for some of
our project.

## Tags and OpenSSL

### 2.2.5 and higher
Use OpenSSL 1.0.2 and higher for Brainpool support.
*Must update brainpool NIDS if compiling with 1.0.2*.

### 2.2.4
This is specific tag we used with an OpenSSL patch
with Brainpool support. If you need Brainpool and
compile this tag with OpenSSL 1.0.2 you will have
some troubles.. Feel free to ask us for the patch.

### 2.2.3 and lower
We used these tags with OpenSSL 0.9.8 fips or 1.0.1a.

