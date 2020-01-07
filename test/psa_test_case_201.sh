# !/bin/bash
#
###############################################################################
# Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# This script is for testing PSA Trusted Storage Linux multi-process
# multi-thread support. The script runs multiple concurrent instances of the
# PSA Storage test application as different users. This tests that multiple
# concurrent execution contexts using the PSA Storage library and sharing the
# storage area co-exist with one another without one process causing error for
# another process.
#
# This script is intended to be run as part of x86 testing where an x86
# version of the test binary PSA_STORAGE_TEST_BIN is run. PSA_STORAGE_TEST_BIN
# implements the test cases. PSA_STORAGE_TEST_BIN can also be built and run
# on the target.
###############################################################################

# Symbols to define the Linux user accounts used to run the applications.
PSA_TEST_201_USER1=testuser1
PSA_TEST_201_USER2=testuser2

# Symbols for commands.
PSA_CMD_ID=id
# psa-storage-example-app needs to be on the PATH
PSA_STORAGE_TEST_BIN=psa-storage-example-app
PSA_CMD_TEST_APP=`which ${PSA_STORAGE_TEST_BIN}`


# Check application is found
_psa_return_status=1
#if [ "${PSA_CMD_TEST_APP}"+ == ""+ ]; then
if [ -z ${PSA_CMD_TEST_APP} ]; then
    echo "Error: ${PSA_STORAGE_TEST_BIN} not found on the path. Set PATH to include test binary directory."
    exit ${_psa_return_status}
fi

# Create the test user accounts
for user in ${PSA_TEST_201_USER1} ${PSA_TEST_201_USER2}
do
    ${PSA_CMD_ID} ${user} > /dev/null 2>&1
    if [ "$?" -eq "1" ]; then
        # user doesnt exist
        sudo useradd ${user}
        sudo usermod --shell /bin/bash ${user}
    fi
done

# Setup the storage area
rm -fR test
mkdir -p test/its
mkdir -p test/pst

# Set world writable property on directories so they can be used by more that the user
# that created them
chmod -R o+w test

# Run 2 instances of the test application binary in parallel, repeating multiple times.
_psa_return_status=0
for i in 0 1 2 3 4 5 6 7 8 9
do
    # Run n copies of the test application simultaneously to test multi-process support.
    # Run the first instance in the background
    sudo runuser -u ${PSA_TEST_201_USER1} -- ${PSA_CMD_TEST_APP} -v &
    _user1_pid=$!

    # run the second instance in the foreground so the script doesnt terminate
    sudo runuser -u ${PSA_TEST_201_USER2} -- ${PSA_CMD_TEST_APP} -v &
    _user2_pid=$!

    wait ${_user1_pid}
    _user1_exit_status=$?
    wait ${_user2_pid}
    _user2_exit_status=$?

    echo "instance 1 return status="${_user1_exit_status}
    echo "instance 2 return status="${_user2_exit_status}

    if [ "${_user1_exit_status}"+ != "0"+ ] || [ "${_user2_exit_status}"+ != "0"+ ]; then
        # set a failure return code
        _psa_return_status=1
    fi
done

# Delete the test accounts
for user in ${PSA_TEST_201_USER1} ${PSA_TEST_201_USER2}
do
    ${PSA_CMD_ID} ${user} > /dev/null 2>&1
    if [ "$?" -eq "1" ]; then
    sudo userdel -r ${user}
    fi
done

exit ${_psa_return_status}