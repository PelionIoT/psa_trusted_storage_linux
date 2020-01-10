# PSA Storage Library Development `Makefile`

## Summary

This document provides instructions about how to use `<topdir>/test/Makefile`.
The purpose of this Makefile is to facilitate development by:
- Providing a makefile target which creates the workspace from dependent projects.
  Compatible versions of the GitHub projects are selected.
- Providing makefile targets for building and running x86 test binaries.

This makefile provides support for building the x86 PSA storage tests:
 - `psa-arch-test-ps`, a test binary generated from the PSA Compliance project
   psa-arch-test.
 - psa_trusted_storage_linux test binary (derived from the mbed-crypto
   tests) e.g. `psa-storage-example-app`.

In order to run the above, use this makefile in the following way:
 1. Copy this makefile into a new top level workspace directory TOPDIR.
 2. cd into TOPDIR and invoke the following commands.
 3. make ws-create-pinned
 4. make
 5. make test

Item 3 above git clones the relevant repositories at compatible pinned versions.
The projects of interest are:
 - https://github.com/ARMmbed/psa_trusted_storage_linux.
 - https://github.com/ARMmbed/mbed-crypto.
 - https://github.com/ARM-software/psa-arch-tests.

Item 4 above builds test binaries e.g. `psa-arch-tests-ps`.

Item 5 above runs the test binaries and outputs the test trace to the console.


## Required Tools
The following tools are required on the host and available on the path:
- Git.
- Repo.
- Host gcc compiler.

