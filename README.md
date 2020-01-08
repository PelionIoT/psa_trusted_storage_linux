# PSA Storage Library

## Summary

The PSA storage library is a reference implementation of the [protected storage interface][1] of the Arm Platform Security Architecture (PSA). This is a preview release provided for evaluation purposes only.

PSA storage library is distributed under the Apache License, version 2.0. See the LICENSE file for the full text of the license.

The library implements the protected storage API as defined in protected_storage.h.


## Compiling

You need the following tools to build the library with the provided makefiles:

* GNU Make.
* A C99 toolchain (compiler, linker, archiver).

If you have a C compiler, such as GCC or Clang, just run `make` in the top-level directory to build the library and the example application.

```
make
```

To select a different compiler, set the `CC` variable to the name or path of the compiler and linker (default: `cc`), and set `AR` to a compatible archiver (default: `ar`). For example:
```
make CC=arm-linux-gnueabi-gcc AR=arm-linux-gnueabi-ar
```

## Example programs

To install the build artifacts in the `usr/local` sub-directory of the top-level directory, do the `make install` command as follows:

```
make install prefix=${PWD}/usr/local/
```

After installation the example program will be available in `usr/local/bin`. To run the program do the following:

```
export LD_LIBRARY_PATH=${PWD}/usr/local/lib
usr/local/bin/psa-storage-example-app
```

## Notes for client applications

### Protected storage API support

[The PSA Storage API Specification v1.0][1] specifies the protected storage API functions psa_ps_create() and psa_ps_set_extended() are optional. 
This PSA Storage library currently does not implement these functions.

### Multi-threaded applications

[The PSA Storage API Specification v1.0][1] says the following regarding multi-thread application support: 

*Consistency: In this API, each operation is individually atomic. A multi-threaded application using this API must not be
able to observe any intermediate state in the data assets. If thread B calls the API while thread A is in the
middle of an operation that modifies a data asset, thread B must either see the state of the asset before
or the state of the asset after the operation requested by thread A.*

The implementation is conformant with the above statement, but the library does not perform synchronization between threads.
Multi-threaded applications MUST perform worker thread synchronisation if this is required.

The following example helps illustrate the problem.

Consider an applicaton with N+1 worker threads where N producer threads write a sensor reading to a shared object UID1, and
1 consumer thread reads the value from UID1. A producer thread may only write UID1 when its value is -1. After reading
UID1 the consumer thread resets the UID1 by writing -1. The initial UID1 value is -1. No sensor readings from the producer threads
should be lost and not read by the consumer.

It's possible that the N producer threads all observe the UID1 value to be -1 and concurrently attempt to write the UID1 data with
their sensor reading. With no thread synchronisation provided by the application it is indeterminate which of the N
producer readings will be read by the consumer. This is because one producer thread write operation may overwrite
another producers value without the reader observing the change.


[1]: https://github.com/ARM-software/psa-arch-tests/blob/master/api-specs/storage/v1.0/doc/IHI0087-PSA_Storage_API-1.0.0.pdf