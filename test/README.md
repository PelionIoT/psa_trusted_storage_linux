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
 - psa_trusted_storage_linux test binaries (derived from the mbed-crypto
   tests) e.g. `psa-storage-example-app`.

(WARNING: Public users will be unable to use this makefile to generate
psa-arch-test-ps due to repo access restrictions. However, other test
binaries can be generated. See later for more details.)

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
 - A private fork of https://github.com/ARM-software/psa-arch-tests. The private
   fork contains patches against upstream so that psa-arch-tests-ps can be built.
   The fork is accessible to ARM stakeholders for internal development. In time,
   the patches will be upstreamed and become publicly availble.

Item 4 above builds test binaries. ARM developers can build all test binaries
including psa-arch-tests-ps by using the following command:
 - make all-arm

Item 5 above runs the test binaries and outputs the test trace to the console.


## Required Tools
The following tools are required on the host and available on the path:
- Git.
- Repo.
- Host gcc compiler.

