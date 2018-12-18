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

## RHEL55

### Dependencies

To avoid library conflicts, we have to compile the dependencies passing the
`-rpath <dir>` argument to the linker. The `-rpath` forces the compiled binary
to load the dynamic libraries from the passed directory, avoiding any conflict
with libraries installed in the RHEL55's default LIBRARY_PATH (i.e.: 
/lib and /usr/lib).

In this tutorial we are using the default OpenSSL and LibP11 installation
directories (i.e.: `/usr/local/ssl` and `/usr/local`). If you want to change
the installation location, for both cases, you can use the `--prefix <dir>`
parameter in the configuration to set the installation's base directory. If you
do so, you have to change the `-rpath <dir>`, `-L <dir>` and `-I <dir>`
parameters to point to the new installation directory set with the 
`--prefix <dir>` parameter.

 * OpenSSL 1.0.2g

```bash
tar -xvf openssl-1.0.2q.tar.gz
cd openssl-1.0.2q
./config shared -Wl,-rpath -Wl,/usr/local/ssl/lib -L/usr/local/ssl/lib -I/usr/local/ssl/include
make
su -
make install
```

 * LibP11 0.4.9

```bash
tar -xvf libp11-0.4.9.tar.gz
cd libp11-0.4.9
OPENSSL_CFLAGS=-I/usr/local/ssl/include OPENSSL_LIBS="-Wl,-rpath -Wl,/usr/local/ssl/lib -L/usr/local/ssl/lib -lcrypto -ldl -lz" ./configure
make
su -
make install
```

### Compilation

```bash
export OPENSSL_PREFIX=/usr/local/ssl
export LIBP11_PREFIX=/usr/local
make -f Makefile.rhel55
```

or

`OPENSSL_PREFIX=/usr/local/ssl LIBP11_PREFIX=/usr/local make -f Makefile.rhel55`

