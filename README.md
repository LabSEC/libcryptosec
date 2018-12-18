Libcryptosec
===========
Object Oriented Wrapper for the OpenSSL libcrypto library. 

[![Build Status](https://travis-ci.org/LabSEC/libcryptosec.svg?branch=master)](https://travis-ci.org/LabSEC/libcryptosec)

## Contributions

* We take in pull requests, feel free to fork :-)
* the Master and Dev branches are protected. Use branches and 
pull requests.
* Avoid backwards incompability! We use this for many of our project.
* OpenSSL 1.1.x support is not in the roadmap, but we might make a compilation target for it soon.


## Compilation

* Requires OpenSSL-dev libraries (```libssl-dev``` for ubuntu or ```openssl-dev``` for fedora);
* Requires libp11 library (```libp11-dev`` for ubuntu or ```libp11-devel``` for fedora);
* ```$make``` for dynamic linking with OpenSSL;
* ```$make static``` for static linking with OpenSSL;
* ```$make install``` to copy header files to ```/usr/include``` and shared object to ```/usr/lib``` or ```/usr/lib64```, depending on system ARQ..

## Tests

As bugs are reported, we create tests before we fix them. Unfortunately, a full test suite is not priority right now.
Depending on how you compiled the library, make use of the corret test recipe:

* ```make test_dynamic``` runs tests with dynamic linked compilation;
* ```make test_static``` runs tests with static linked compilation;
* ```make installed_test_dynamic``` runs tests with dynamic linked compilation using installed files;
* ```make installed_test_static``` runs tests with static linked compilation using installed files;
* ```make test_enfing_dynamic``` runs ENGINE tests only, with dynamic linked compilation;
* ```make test_enfing_static``` runs ENGINE tests only, with static linked compilation;

Make sure you fill in the engine test variables at ```/test/src/unit/EngineTest.cpp```

```
 #define PATH ""
 #define ID ""
 #define ADDR ""
 #define PORT ""
 #define USER ""
 #define PW ""
 #define KEY ""
```

If a non-engine test is called before an Engine test, make sure you call ```make clean```, to force the engine compilation flags through all test files.

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

