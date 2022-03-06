#!/bin/sh
# NEGATIVE Test: test_cryptocopy should fail when password not provided with encrypt/decrypt option

/bin/rm -rf input.txt output.txt

#/bin/cp in_test.txt input.txt
echo "Hello CSE-506" > input.txt

./test_cryptocopy -e input.txt output.txt
retval=$?
if test $retval != 0 ; then
	echo "test_cryptocopy failed with error: $retval, password can't be empty with encrypt/decrypt option"
else
	echo test_cryptocopy success
fi