# PSA Storage Library

## Summary

The PSA storage library is a reference implementation of the protected storage interface of the Arm Platform Security Architecture (PSA). This is a preview release provided for evaluation purposes only.

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

