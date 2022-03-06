#!/bin/sh
# NEGATIVE Test: test_cryptocopy should fail when multiple options (encryption/decryption/copy) provided 

/bin/rm -rf input.txt output.txt

#/bin/cp in_test.txt input.txt
echo "Hello CSE-506" > input.txt

./test_cryptocopy -e -d -p "HelloWorld" input.txt output.txt
retval=$?
if test $retval != 0 ; then
	echo test_cryptocopy failed with error: $retval, only one of encryption/decryption/copy should be provided
else
	echo test_cryptocopy success
fi
